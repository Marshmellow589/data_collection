import os

def is_virtual_env(path):
    return os.path.exists(os.path.join(path, 'bin', 'activate')) or os.path.exists(os.path.join(path, 'Scripts', 'activate'))

def list_virtual_envs(folder):
    virtual_envs = []
    for item in os.listdir(folder):
        item_path = os.path.join(folder, item)
        if os.path.isdir(item_path) and is_virtual_env(item_path):
            virtual_envs.append(item)
    return virtual_envs

folder_path = r'/mnt/d/deepseek_project/material_inspection/data_collection'  # Replace with the path to your folder
virtual_envs = list_virtual_envs(folder_path)

print(f"Found {len(virtual_envs)} virtual environments in the folder:")
for env in virtual_envs:
    print(env)
