import secrets
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import json
import os
import random
import uuid
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# -------------------------------------------------
# STORAGE
# -------------------------------------------------
USER_DATA = {}  # Menyimpan username, password hash, dan RSA keys
MESSAGES = []
LAST_MESSAGE_ID = 0
ACTIVE_USERS = {}  # key=username, value=set of tab_ids

DATA_FILE = 'chat_data.json'

def load_data():
    global USER_DATA, MESSAGES, LAST_MESSAGE_ID
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
            USER_DATA = data.get('user_data', {})
            MESSAGES = data.get('messages', [])
            if MESSAGES:
                LAST_MESSAGE_ID = max(msg.get('id', 0) for msg in MESSAGES)
            else:
                LAST_MESSAGE_ID = 0
    print(f"DATA LOADED — Users: {len(USER_DATA)}, Messages: {len(MESSAGES)}, Last ID: {LAST_MESSAGE_ID}")

def save_data():
    data = {
        'user_data': USER_DATA,
        'messages': MESSAGES
    }
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    print("DATA SAVED")

load_data()

# -------------------------------------------
# RSA FUNCTIONS
# -------------------------------------------
def generate_rsa_keys(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 17
    d = pow(e, -1, phi_n)
    return ((e, n), (d, n))

def rsa_encrypt(plaintext_bytes, e, n):
    return [pow(byte, e, n) for byte in plaintext_bytes]

def rsa_decrypt(ciphertext, d, n):
    return [pow(byte, d, n) for byte in ciphertext]

def message_to_ascii(msg):
    return list(msg.encode('utf-8'))

def ascii_to_message_rsa(arr):
    return bytes([x % 256 for x in arr]).decode('utf-8', errors='replace')

# -------------------------------------------
# PASSWORD UTILS
# -------------------------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'tab_id' not in session:
        session['tab_id'] = str(uuid.uuid4())

    tab_key = "username_" + session['tab_id']
    current_user = session.get(tab_key)

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return render_template('index.html', view='login', error="Username atau password kosong")

        if username not in USER_DATA:
            # generate RSA keys
            p = random.choice([61, 71, 73, 83, 89])
            q = random.choice([53, 59, 67, 79, 89])
            pub_key, priv_key = generate_rsa_keys(p, q)
            color = "#" + secrets.token_hex(3)

            USER_DATA[username] = {
                'password_hash': hash_password(password),
                'public': pub_key,
                'private': priv_key,
                'color': color
            }
            save_data()

        if USER_DATA[username]['password_hash'] != hash_password(password):
            return render_template('index.html', view='login', error="Password salah")

        session[tab_key] = username

        # Update ACTIVE_USERS per tab
        if username not in ACTIVE_USERS:
            ACTIVE_USERS[username] = set()
        ACTIVE_USERS[username].add(session['tab_id'])

        return redirect(url_for('home'))

    if current_user:
        user_key_data = USER_DATA.get(current_user)
        d, n = user_key_data['private']

        decrypted_messages = []
        for msg in MESSAGES:
            if msg['recipient'].lower() == current_user.lower() or msg['sender'].lower() == current_user.lower():

                # === PERBAIKAN UTAMA ===
                # Jika pesan kita sendiri, langsung pakai plaintext
                if 'plaintext' not in msg:
                    if msg['recipient'].lower() == current_user.lower():
                        decrypted_ascii = rsa_decrypt(msg['ciphertext'], d, n)
                        plaintext = ascii_to_message_rsa(decrypted_ascii)
                    else:  # pesan kita sendiri
                        plaintext = msg.get('plaintext', "")
                        decrypted_ascii = message_to_ascii(plaintext)
                    msg['plaintext'] = plaintext
                    save_data()
                else:
                    if msg['recipient'].lower() == current_user.lower():
                        decrypted_ascii = rsa_decrypt(msg['ciphertext'], d, n)
                    else:
                        decrypted_ascii = message_to_ascii(msg['plaintext'])
                    plaintext = msg['plaintext']

                decrypted_messages.append({
                    'id': msg['id'],
                    'sender': msg['sender'].capitalize(),
                    'ciphertext': msg['ciphertext'],
                    'plaintext': plaintext,
                    'decrypted_ascii': decrypted_ascii,
                    'color': USER_DATA.get(msg['sender'], {}).get('color', '#777')
                })

        return render_template(
            'index.html',
            view='chat',
            current_user=current_user.capitalize(),
            user_key_data=user_key_data,
            all_users=USER_DATA,
            messages=decrypted_messages
        )

    return render_template('index.html', view='login')

@app.route('/logout')
def logout():
    if 'tab_id' in session:
        current_tab = session.get('tab_id', '')
        tab_key = "username_" + current_tab
        username = session.get(tab_key, '').lower()

        if username in ACTIVE_USERS:
            ACTIVE_USERS[username].discard(current_tab)
            if not ACTIVE_USERS[username]:
                del ACTIVE_USERS[username]

        session.pop(tab_key, None)

    return redirect(url_for('home'))

@app.route('/send', methods=['POST'])
def send_message():
    global LAST_MESSAGE_ID

    data = request.json
    sender = data.get('sender', '').lower()
    recipient = data.get('recipient', '').lower()
    message = data.get('message', '')

    if not sender or not recipient or not message:
        return jsonify({'success': False, 'error': 'Data invalid'}), 400

    if recipient not in USER_DATA:
        return jsonify({'success': False, 'error': 'User tidak ditemukan'}), 404

    # Ambil public key penerima
    e, n = USER_DATA[recipient]['public']
    ascii_list = message_to_ascii(message)
    ciphertext = rsa_encrypt(ascii_list, e, n)

    LAST_MESSAGE_ID += 1
    new_msg = {
        'id': LAST_MESSAGE_ID,
        'sender': sender,
        'recipient': recipient,
        'ciphertext': ciphertext,
        'plaintext': message  # simpan plaintext supaya chat kita muncul kembali
    }

    MESSAGES.append(new_msg)
    save_data()

    return jsonify({
        'success': True,
        'ciphertext': ciphertext,
        'ascii_list': ascii_list,
        'recipient': recipient,
        'sender_color': USER_DATA.get(sender, {}).get('color', '#777')
    })

@app.route('/get_messages_api')
def get_messages_api():
    user = request.args.get('user', '').lower()
    last_id = int(request.args.get('last_id', 0))

    if user not in USER_DATA:
        return jsonify({'messages': []})

    d, n = USER_DATA[user]['private']
    new_msgs = []

    for msg in MESSAGES:
        if msg['id'] > last_id and (msg['recipient'].lower() == user or msg['sender'].lower() == user):
            if msg['sender'].lower() == user:
                plaintext = msg.get('plaintext', "")
                decrypted_ascii = message_to_ascii(plaintext)
            else:
                decrypted_ascii = rsa_decrypt(msg['ciphertext'], d, n)
                plaintext = ascii_to_message_rsa(decrypted_ascii)
                msg['plaintext'] = plaintext  # pastikan selalu ada

            new_msgs.append({
                'id': msg['id'],
                'sender': msg['sender'].capitalize(),
                'ciphertext': msg['ciphertext'],
                'plaintext': plaintext,
                'decrypted_ascii': decrypted_ascii,
                'color': USER_DATA.get(msg['sender'], {}).get('color', '#777')
            })

    return jsonify({'messages': new_msgs})

@app.route('/get_users_api')
def get_users_api():
    current_tab = "username_" + session.get('tab_id', '')
    current_user = session.get(current_tab, '').lower()

    users_with_data = {
        name.lower(): {'color': USER_DATA[name]['color']}
        for name in ACTIVE_USERS
        if name.lower() != current_user
    }
    return jsonify({'users': users_with_data})

@app.route('/delete_message/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    global MESSAGES

    target = next((m for m in MESSAGES if m['id'] == message_id), None)

    if not target:
        return jsonify({'success': False, 'error': 'Pesan tidak ditemukan'}), 404

    current_tab = "username_" + session.get('tab_id', '')
    current_user = session.get(current_tab, '').lower()

    if target['sender'] != current_user and target['recipient'] != current_user:
        return jsonify({'success': False, 'error': 'Tidak punya akses'}), 403

    MESSAGES = [m for m in MESSAGES if m['id'] != message_id]
    save_data()

    return jsonify({'success': True, 'message_id': message_id})

@app.route('/delete_all_messages', methods=['DELETE'])
def delete_all_messages():
    global MESSAGES

    current_tab = "username_" + session.get('tab_id', '')
    current_user = session.get(current_tab, '').lower()

    if not current_user:
        return jsonify({'success': False, 'error': 'User tidak ditemukan'}), 403

    MESSAGES = [m for m in MESSAGES if m['sender'] != current_user and m['recipient'] != current_user]
    save_data()

    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, port=5006)
