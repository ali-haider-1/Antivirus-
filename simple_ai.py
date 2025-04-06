import os




def yara_scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            scan_with_yara(file_path)

# Example usage
if __name__ == "__main__":
    scan_directory = '/Users/apple/Documents/clients'  # Replace with the directory you want to scan
    yara_scan_directory(scan_directory)
