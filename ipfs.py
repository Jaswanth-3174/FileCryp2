import requests

def upload_to_fleek(file_path, api_key):
    fleek_url = "https://api.fleek.co/storage/upload"
    
    headers = {
        'Authorization': f'Bearer {api_key}'
    }

    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(fleek_url, headers=headers, files=files)

            if response.status_code == 200:
                result = response.json()
                fleek_url = result.get('publicUrl')
                print("File uploaded successfully. Fleek URL:", fleek_url)
            else:
                print("Failed to upload the file. Status code:", response.status_code)

    except Exception as e:
        print("An error occurred:", str(e))

# Example usage
upload_to_fleek(r'D:\temp\static\images\b.png', '4x8ioW+YJCMzR6MKmbt1ZQ==')
