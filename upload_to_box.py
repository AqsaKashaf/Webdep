
import json, sys
from boxsdk import Client
from boxsdk.auth.ccg_auth import CCGAuth
from pathlib import Path

class BoxClient:
    def __init__(self):
        self.client_id = "s3e4dg4x9o33dd46hek5gfjogd40nlni"
        self.root_folder_id = "182556826473"
        self.enterprise_id = "81467"
        self.client = None

        self.init_client()

    def init_client(self):
        credentials_file = open(f"{Path.home()}/.secrets/credentials.json")
        data = json.load(credentials_file)
        auth = CCGAuth(
            client_id=self.client_id,
            client_secret=data["box_client"],
            enterprise_id=self.enterprise_id,
        )
        self.client = Client(auth)

    def upload_file(self,filepath,filename):
        month = filename.split("-")[-1]
        folder_name = f'data-{month}'

        subfolders = self.client.folder(folder_id=self.root_folder_id).get_items()
        folder_exists = False
        target_folder = None
        for subfolder in subfolders:
            if subfolder.name == folder_name:
                folder_exists = True
                target_folder = subfolder
                break
        if(not folder_exists):
            target_folder = self.client.folder(self.root_folder_id).create_subfolder(folder_name)
        
        filesize = Path(filepath).stat().st_size
        if(filesize > 20000000):
            chunked_uploader = self.client.folder(target_folder.id).get_chunked_uploader(file_path=filepath, file_name=filename)
            uploaded_file = chunked_uploader.start()
        else:
            uploaded_file  = self.client.folder(target_folder.id).upload(file_path=filepath, file_name=filename)
        
        print(f'File "{uploaded_file.name}" uploaded to Box with file ID {uploaded_file.id}')


def main():
    box_client = BoxClient()
    file_to_upload = sys.argv[1]
    new_filename = sys.argv[2]
    box_client.upload_file(file_to_upload,new_filename)

if __name__ == "__main__":
    main()
    
