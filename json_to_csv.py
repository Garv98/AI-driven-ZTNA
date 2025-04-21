import json
import csv

def json_to_csv(json_file, csv_file):
    with open(json_file, 'r', encoding='utf-8-sig') as f:  # Change encoding to utf-8-sig
        data = json.load(f)

    # Ensure the data is a list of dictionaries
    if isinstance(data, dict):  
        data = [data]  

    # Extract field names from keys of the first dictionary
    field_names = data[0].keys()

    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=field_names)
        writer.writeheader()
        writer.writerows(data)

    print(f"CSV file '{csv_file}' created successfully.")

# Example Usage
json_to_csv(r'C:\Users\garva\Downloads\brute_force_data.json', 
            r'C:\Users\garva\OneDrive\Desktop\4th sem EL\dataset.csv')
