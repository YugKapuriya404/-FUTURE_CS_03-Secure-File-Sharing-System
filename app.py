from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
from encryption import FileEncryptor
import io

app = Flask(__name__)
app.secret_key = 'abcdefg'  
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

@app.route('/')
def index():
    """Home page with encrypt/decrypt forms"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and encryption - sends encrypted file directly to browser"""
    if 'file' not in request.files or 'key' not in request.form:
        flash('Please select a file and enter encryption key', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    encryption_key = request.form['key']
    
    if file.filename == '' or encryption_key == '':
        flash('Please select a file and enter encryption key', 'error')
        return redirect(url_for('index'))
    
    if file:
        try:
            # Initialize encryptor with user's key
            encryptor = FileEncryptor(password=encryption_key)
            
            # Read file data
            file_data = file.read()
            original_filename = secure_filename(file.filename)
            
            # Encrypt the file
            encrypted_data = encryptor.encrypt_file(file_data, original_filename)
            
            # Generate filename for download
            encrypted_filename = f"{original_filename}.enc"
            
            # Create the encrypted file format (salt + nonce + tag + ciphertext)
            encrypted_file_bytes = (
                encrypted_data['salt'] +
                encrypted_data['nonce'] +
                encrypted_data['tag'] +
                encrypted_data['ciphertext']
            )
            
            # Send encrypted file directly to browser for download
            return send_file(
                io.BytesIO(encrypted_file_bytes),
                as_attachment=True,
                download_name=encrypted_filename,
                mimetype='application/octet-stream'
            )
            
        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
            return redirect(url_for('index'))
    
    flash('Upload failed', 'error')
    return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt_file_upload():
    """Handle file decryption and download"""
    if 'file' not in request.files or 'key' not in request.form:
        flash('Please select a file and enter decryption key', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    decryption_key = request.form['key']
    
    if file.filename == '' or decryption_key == '':
        flash('Please select a file and enter decryption key', 'error')
        return redirect(url_for('index'))
    
    try:
        # Initialize encryptor with user's key
        encryptor = FileEncryptor(password=decryption_key)
        
        # Read encrypted file
        encrypted_file_data = file.read()
        
        # Parse encrypted data
        salt = encrypted_file_data[0:16]
        nonce = encrypted_file_data[16:32]
        tag = encrypted_file_data[32:48]
        ciphertext = encrypted_file_data[48:]
        
        encrypted_data = {
            'salt': salt,
            'nonce': nonce,
            'tag': tag,
            'ciphertext': ciphertext
        }
        
        # Decrypt file
        decrypted_data = encryptor.decrypt_file(encrypted_data)
        
        # Generate download filename
        original_name = file.filename.replace('.enc', '')
        if not original_name or original_name == file.filename:
            original_name = 'decrypted_file.txt'
        
        # Send decrypted file to user
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=original_name
        )
    except Exception as e:
        flash(f'Decryption failed: Wrong key or corrupted file', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    print(" Secure File Encryption System Starting...")
    print(" Files are NOT stored on server - direct download only")
    print(" Open your browser and go to: http://127.0.0.1:5000")
    print("\n  SECURITY NOTE: This is a basic implementation for learning.")
    print("    For production use, implement HTTPS, user authentication, and secure key storage.\n")
    app.run(debug=True)