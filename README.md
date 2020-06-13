# observer
A simple static analysis tool to determine file maliciousness.

## Requirements:

1. A running instance of MongoDB is required for Observer to compare and store local file hashes.
2. Python 3.5+
3. VirusTotal API Key

## Installation:

1. Clone the repository into local machine. `git clone https://github.com/DeveshChande/observer`
2. Start up a local instance of MongoDB.
3. Ensure that you have a MongoDB database named 'localhashes' which has collections named 'md5hash' and 'magic_number_data'.
4. Import magic_number_data.json into MongoDB using 'mongoimport --db localhashes --collection magic_number_data --file '[path_to_file]' --jsonArray'
5. Enter VirusTotal API Key under the virus_total_check function

## Execution:

`python3 observer.py [file_name]`

