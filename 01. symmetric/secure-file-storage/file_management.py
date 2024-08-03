import os

class FileManagementModule:
    def __init__(self, storage_dir):
        self.storage_dir = storage_dir
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
    
    def save_file(self, file_name, data):
        with open(os.path.join(self.storage_dir, file_name), 'wb') as f:
            f.write(data)
        
    def read_file(self, file_name):
        with open(os.path.join(self.storage_dir, file_name), 'rb') as f:
            return f.read()
    
    def list_files(self):
        return os.listdir(self.storage_dir)