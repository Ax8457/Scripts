import hivex
import sys

def list_subkeys(hive, key, path=""):
    if key is None:
        print(f"[X] Key '{path}' doesn't exist")
        return []
    subkeys = hive.node_children(key)
    if not subkeys:
        print(f"\n[X] No subkey found for: {path}")
        list_values(hive, key, path)
        return []
    print(f"\n[+] Subkeys found in '{path}':")
    for subkey in subkeys:
        subkey_name = hive.node_name(subkey)
        print(f"    - {subkey_name}")
    return subkeys

def decode_value(value_data):
    if isinstance(value_data, tuple):
        value_data = value_data[1]  
    if isinstance(value_data, bytes):
        try:
            decoded_data = value_data.decode("utf-16le").strip("\x00")
            if all(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in decoded_data):
                return decoded_data
        except UnicodeDecodeError:
            pass 
        return value_data.hex()
    return value_data

def list_values(hive, key, path):
    values = hive.node_values(key)
    if not values:
        print(f"[X] No values found in {path}")
        return
    print(f"\n[+] Values in {path}:")
    for value in values:
        value_name = hive.value_key(value)
        value_data = decode_value(hive.value_value(value))
        print(f"    - {value_name}: {value_data}")

def parse_registry(hive):
    key = hive.root()
    #list_subkeys(hive, key, "ROOT")
    current_path = ""
    
    while True:
        path_element = input("RegistryParser> Enter a subkey (or 'exit' to leave): ")
        if path_element.lower() == 'exit':
            break
        key = hive.node_get_child(key, path_element)
        if key is None:
            print(f"[X] Subkey '{path_element}' doesn't exist")
            continue
        current_path = f"{current_path}\\{path_element}" if current_path else path_element
        subkeys = list_subkeys(hive, key, current_path)
        if not subkeys:
            list_values(hive, key, current_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 registryParser.py <DAT file or registry file>")
        sys.exit(1)
    hive = hivex.Hivex(sys.argv[1], write=False)
    parse_registry(hive)
