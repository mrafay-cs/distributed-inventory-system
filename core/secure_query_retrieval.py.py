import hashlib
import json
from pathlib import Path

# task 3: multi-signature query verification and secure delivery
# file is for the secure retrieval part of the assignment
# the procurement officer asks for an item quantity
# the inventory nodes approve the result using harn multi-signature
# then the approved response is encrypted and recovered by the procurement officer


# gets the folder where python file is saved
# it helps the program find the json files in the same folder
BASE_DIR = Path(__file__).resolve().parent


# these are the 4 inventory record/database files
# each inventory node has its own local database file
record_files = {
    "Inventory A": "inventory_a_records.json",
    "Inventory B": "inventory_b_records.json",
    "Inventory C": "inventory_c_records.json",
    "Inventory D": "inventory_d_records.json"
}


# these are the 4 inventory parameter files
# for task 3, each node needs an identity and random value for harn multi-signature
inventory_param_files = {
    "Inventory A": "inventory_a_params.json",
    "Inventory B": "inventory_b_params.json",
    "Inventory C": "inventory_c_params.json",
    "Inventory D": "inventory_d_params.json"
}


# file stores the pkg rsa values
# the pkg is used to generate harn identity-based secret keys
pkg_file = "pkg_keys.json"


# file stores the procurement officer rsa values
# the procurement officer keys are used for secure response delivery
procurement_file = "procurement_officer_keys.json"


def load_json_file(file_name):
    # loads one json file from the same folder as python file
    # highlighting that we proves are using separate files
    file_path = BASE_DIR / file_name

    with open(file_path, "r", encoding="utf-8-sig") as file:
        return json.load(file)


def save_json_file(file_name, data):
    # saves updated values back into the json file
    # used after n, phi, and d are calculated
    file_path = BASE_DIR / file_name

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def load_inventory_databases():
    # loads all four inventory database files
    # simulates each inventory node having its own local database
    databases = {}

    for node_name, file_name in record_files.items():
        databases[node_name] = load_json_file(file_name)

    return databases


def load_inventory_params():
    # loads all four inventory parameter files
    # each file gives the identity and random value for that inventory node
    params = {}

    for node_name, file_name in inventory_param_files.items():
        params[node_name] = load_json_file(file_name)

    return params


def extended_gcd(a, b):
    # helper function for modular inverse
    # using to calculate the rsa private exponent d
    if a == 0:
        return b, 0, 1

    gcd_value, x1, y1 = extended_gcd(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return gcd_value, x, y


def mod_inverse(e, phi):
    # calculates the modular inverse
    #  rsa, gives d where e * d mod phi = 1
    gcd_value, x, _ = extended_gcd(e, phi)

    if gcd_value != 1:
        raise ValueError("modular inverse does not exist.")

    return x % phi


def generate_rsa_values(key_data):
    # the json files give p, q, and e
    # function calculates the extra rsa values needed:
    # n, phi(n), and d
    p = key_data["p"]
    q = key_data["q"]
    e = key_data["e"]

    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)

    key_data["n"] = n
    key_data["phi"] = phi
    key_data["d"] = d

    return key_data


def initialise_parameters(pkg_keys, procurement_keys, inventory_params):
    # setup stage for task 3
    # calculates rsa values for the pkg and the procurement officer
    # prints the inventory identity and random values
    print("\n========== parameter initialisation ==========")

    generate_rsa_values(pkg_keys)
    generate_rsa_values(procurement_keys)

    # saving these back to the files hshowing computed values clearlyt
    save_json_file(pkg_file, pkg_keys)
    save_json_file(procurement_file, procurement_keys)

    print("\npkg key values")
    print(f"p = {pkg_keys['p']}")
    print(f"q = {pkg_keys['q']}")
    print(f"e = {pkg_keys['e']}")
    print(f"n = p * q = {pkg_keys['n']}")
    print(f"phi(n) = (p - 1) * (q - 1) = {pkg_keys['phi']}")
    print(f"d = e^-1 mod phi(n) = {pkg_keys['d']}")
    print(f"updated pkg file saved: {pkg_file}")

    print("\nprocurement officer key values")
    print(f"p = {procurement_keys['p']}")
    print(f"q = {procurement_keys['q']}")
    print(f"e = {procurement_keys['e']}")
    print(f"n = p * q = {procurement_keys['n']}")
    print(f"phi(n) = (p - 1) * (q - 1) = {procurement_keys['phi']}")
    print(f"d = e^-1 mod phi(n) = {procurement_keys['d']}")
    print(f"updated procurement officer file saved: {procurement_file}")

    print("\ninventory node harn parameters")
    for node_name, data in inventory_params.items():
        print(f"{node_name}: identity = {data['identity']}, random value = {data['random_value']}")


def find_item_quantity(database_data, item_id):
    # searches one inventory node database for the requested item id
    # if the item exists, it returns the quantity
    for record in database_data["records"]:
        if record["item_id"] == item_id:
            return record["quantity"]

    return None


def submit_query(inventory_databases):
    # where the procurement officer submits a query
    # for example, the user enters 002 to retrieve the quantity of item 002
    print("\n========== query submission ==========")

    item_id = input("procurement officer, enter item id to search, example 002: ").strip()

    if item_id == "":
        item_id = "002"

    print(f"\nquery request: retrieve quantity for item {item_id}")

    results = {}

    # every inventory node checks its own local database file
    for node_name, database_data in inventory_databases.items():
        quantity = find_item_quantity(database_data, item_id)
        results[node_name] = quantity
        print(f"{node_name} returned quantity: {quantity}")

    # the result is only trusted if all nodes return the same quantity
    unique_results = set(results.values())

    if len(unique_results) == 1 and None not in unique_results:
        quantity = unique_results.pop()
        message = f"{item_id}|{quantity}"

        print("\nall inventory nodes returned the same result")
        print(f"query result message for approval: {message}")

        return message

    print("\nquery result is inconsistent or item was not found")
    print("query will not continue to multi-signature approval")

    return None


def multiply_mod(values, n):
    # multiplies a list of values together using mod n
    # used for aggregating t values, s values, and identities
    result = 1

    for value in values:
        result = (result * value) % n

    return result


def hash_t_and_message(t_value, message):
    # h(t,m) is the hash used in harn signing
    # t is the aggregated t value and m is the query result message
    # md5 gives hex, then it is converted to decimal for modular maths
    hash_input = str(t_value) + message
    hash_hex = hashlib.md5(hash_input.encode()).hexdigest()
    hash_decimal = int(hash_hex, 16)

    return hash_input, hash_hex, hash_decimal


def generate_secret_keys(pkg_keys, inventory_params):
    # harn step 1
    # the pkg generates one secret key for each inventory node
    # formula: g_j = id_j^d mod n
    # links each node to its identity
    print("\n========== harn secret key generation ==========")

    secret_keys = {}

    for node_name, data in inventory_params.items():
        identity = data["identity"]

        g_j = pow(identity, pkg_keys["d"], pkg_keys["n"])
        secret_keys[node_name] = g_j

        print(f"\n{node_name}")
        print("formula: g_j = id_j^d mod n")
        print(f"id_j = {identity}")
        print(f"g_j = {g_j}")

    return secret_keys


def generate_t_values(pkg_keys, inventory_params):
    # harn step 2
    # each inventory node generates a t_j value
    # formula: t_j = r_j^e mod n
    # r_j is the random value from that node's parameter file
    print("\n========== harn t value generation ==========")

    t_values = {}

    for node_name, data in inventory_params.items():
        random_value = data["random_value"]

        t_j = pow(random_value, pkg_keys["e"], pkg_keys["n"])
        t_values[node_name] = t_j

        print(f"\n{node_name}")
        print("formula: t_j = r_j^e mod n")
        print(f"r_j = {random_value}")
        print(f"t_j = {t_j}")

    # after each node generates t_j, the values are multiplied together
    aggregated_t = multiply_mod(t_values.values(), pkg_keys["n"])

    print("\naggregated t value")
    print("formula: t = product of all t_j mod n")
    print(f"t = {aggregated_t}")

    return t_values, aggregated_t


def generate_partial_signatures(pkg_keys, inventory_params, secret_keys, aggregated_t, message):
    # harn step 3
    # each inventory node creates its own partial signature s_j
    # formula: s_j = g_j * r_j^h(t,m) mod n
    # these partial signatures are later combined into one multi-signature
    print("\n========== harn partial signature generation ==========")

    hash_input, hash_hex, hash_decimal = hash_t_and_message(aggregated_t, message)

    print(f"h(t,m) input = {hash_input}")
    print(f"h(t,m) md5 hex = {hash_hex}")
    print(f"h(t,m) decimal = {hash_decimal}")

    partial_signatures = {}

    for node_name, data in inventory_params.items():
        g_j = secret_keys[node_name]
        r_j = data["random_value"]

        s_j = (g_j * pow(r_j, hash_decimal, pkg_keys["n"])) % pkg_keys["n"]
        partial_signatures[node_name] = s_j

        print(f"\n{node_name}")
        print("formula: s_j = g_j * r_j^h(t,m) mod n")
        print(f"s_j = {s_j}")

    # final aggregated multi-signature value
    aggregated_s = multiply_mod(partial_signatures.values(), pkg_keys["n"])

    print("\naggregated multi-signature")
    print("formula: s = product of all s_j mod n")
    print(f"s = {aggregated_s}")

    return partial_signatures, aggregated_s


def get_identity_product(pkg_keys, inventory_params):
    # harn verification needs the product of all inventory identities
    # function calculates product(ids) mod n
    identities = []

    for node_data in inventory_params.values():
        identities.append(node_data["identity"])

    return multiply_mod(identities, pkg_keys["n"])


def verify_multi_signature(pkg_keys, inventory_params, aggregated_t, aggregated_s, message):
    # harn step 4
    # verifies the final aggregated multi-signature
    # formula:
    # s^e mod n = product(ids) * t^h(t,m) mod n
    # if left side equals right side, the multi-signature is valid
    print("\n========== multi-signature verification ==========")

    hash_input, hash_hex, hash_decimal = hash_t_and_message(aggregated_t, message)

    identity_product = get_identity_product(pkg_keys, inventory_params)

    left_side = pow(aggregated_s, pkg_keys["e"], pkg_keys["n"])
    right_side = (identity_product * pow(aggregated_t, hash_decimal, pkg_keys["n"])) % pkg_keys["n"]

    print("verification formula:")
    print("s^e mod n = product(ids) * t^h(t,m) mod n")
    print(f"h(t,m) input = {hash_input}")
    print(f"h(t,m) md5 hex = {hash_hex}")
    print(f"h(t,m) decimal = {hash_decimal}")

    print(f"\nleft side  = {left_side}")
    print(f"right side = {right_side}")

    is_valid = left_side == right_side

    print(f"multi-signature result: {'valid' if is_valid else 'invalid'}")

    return is_valid


def multi_signature_consensus(pkg_keys, inventory_params, aggregated_t, aggregated_s, message):
    # after the aggregated signature is created, every node checks it
    # similar to consensus check for the query result
    # if all nodes verify it, the result is approved for delivery
    print("\n========== multi-signature consensus check ==========")

    votes = {}

    for node_name in inventory_params:
        valid = verify_multi_signature(
            pkg_keys,
            inventory_params,
            aggregated_t,
            aggregated_s,
            message
        )

        if valid:
            votes[node_name] = "ACCEPT"
        else:
            votes[node_name] = "REJECT"

        print(f"{node_name} vote: {votes[node_name]}")

    accept_count = list(votes.values()).count("ACCEPT")

    print("\nconsensus summary")
    for node_name, vote in votes.items():
        print(f"{node_name}: {vote}")

    print(f"total ACCEPT votes: {accept_count}")

    if accept_count == 4:
        print("multi-signature consensus result: ACCEPTED")
        return True

    print("multi-signature consensus result: REJECTED")
    return False


def text_to_integer(text):
    # rsa encryption works on integers, not plain text
    # converts a text response like 002|20|OK into a number
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def integer_to_text(number):
    # after decryption, the number is converted back into readable text
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder="big").decode("utf-8")


def encrypt_for_procurement_officer(procurement_keys, response_text):
    # secure delivery step
    # the approved response is encrypted using the procurement officer public key
    # formula: c = m^e mod n
    print("\n========== secure response encryption ==========")

    message_integer = text_to_integer(response_text)

    if message_integer >= procurement_keys["n"]:
        raise ValueError("response message is too large for rsa encryption")

    ciphertext = pow(message_integer, procurement_keys["e"], procurement_keys["n"])

    print(f"plain approved response: {response_text}")
    print(f"response as integer: {message_integer}")
    print("encryption formula: c = m^e mod n")
    print(f"ciphertext = {ciphertext}")

    return ciphertext


def decrypt_by_procurement_officer(procurement_keys, ciphertext):
    # recovery step
    # the procurement officer decrypts using the private key
    # formula: m = c^d mod n
    print("\n========== user side recovery ==========")

    recovered_integer = pow(ciphertext, procurement_keys["d"], procurement_keys["n"])
    recovered_text = integer_to_text(recovered_integer)

    print("decryption formula: m = c^d mod n")
    print(f"recovered integer = {recovered_integer}")
    print(f"recovered response = {recovered_text}")

    return recovered_text


def run_valid_query_workflow(pkg_keys, procurement_keys, inventory_params, inventory_databases):
    # main successful workflow for task 3
    # query -> matching result -> harn multi-signature -> verification -> consensus -> encryption -> recovery
    message = submit_query(inventory_databases)

    if message is None:
        return

    # generate the harn values
    secret_keys = generate_secret_keys(pkg_keys, inventory_params)
    t_values, aggregated_t = generate_t_values(pkg_keys, inventory_params)

    # generate and aggregate the partial signatures
    partial_signatures, aggregated_s = generate_partial_signatures(
        pkg_keys,
        inventory_params,
        secret_keys,
        aggregated_t,
        message
    )

    # verify the final multi-signature once before consensus
    valid_signature = verify_multi_signature(
        pkg_keys,
        inventory_params,
        aggregated_t,
        aggregated_s,
        message
    )

    if not valid_signature:
        print("multi-signature failed, response will not be sent")
        return

    # each node checks the same aggregated multi-signature
    consensus_ok = multi_signature_consensus(
        pkg_keys,
        inventory_params,
        aggregated_t,
        aggregated_s,
        message
    )

    if not consensus_ok:
        print("inventory nodes did not agree on the multi-signature")
        return

    # only after approval, the response is prepared and encrypted
    approved_response = message + "|OK"

    ciphertext = encrypt_for_procurement_officer(procurement_keys, approved_response)
    recovered_response = decrypt_by_procurement_officer(procurement_keys, ciphertext)

    print("\n========== final recovery check ==========")
    print(f"approved response = {approved_response}")
    print(f"recovered response = {recovered_response}")

    if approved_response == recovered_response:
        print("recovery result: SUCCESS")
    else:
        print("recovery result: FAILED")


def run_tampered_result_test(pkg_keys, inventory_params):
    # test proves that changing the result breaks verification
    # the signature is created for the original result
    # then the same signature is checked against a changed result
    print("\n========== tampered query result test ==========")

    original_message = input("enter original approved result, example 002|20: ").strip()
    tampered_message = input("enter tampered result, example 002|21: ").strip()

    if original_message == "":
        original_message = "002|20"

    if tampered_message == "":
        tampered_message = "002|21"

    print(f"\noriginal approved result = {original_message}")
    print(f"tampered result = {tampered_message}")

    # create a valid multi-signature for the original message
    secret_keys = generate_secret_keys(pkg_keys, inventory_params)
    t_values, aggregated_t = generate_t_values(pkg_keys, inventory_params)

    partial_signatures, aggregated_s = generate_partial_signatures(
        pkg_keys,
        inventory_params,
        secret_keys,
        aggregated_t,
        original_message
    )

    print("\nchecking the same signature against the tampered result")

    # this should fail because the message has changed
    verify_multi_signature(
        pkg_keys,
        inventory_params,
        aggregated_t,
        aggregated_s,
        tampered_message
    )


def main():
    print("secure dlt-based inventory management system")
    print("task 3: multi-signature query verification and secure delivery")

    # load all json files needed for task 3
    inventory_databases = load_inventory_databases()
    inventory_params = load_inventory_params()
    pkg_keys = load_json_file(pkg_file)
    procurement_keys = load_json_file(procurement_file)

    # show setup values first
    initialise_parameters(pkg_keys, procurement_keys, inventory_params)

    while True:
        print("\n==============================================")
        print("secure dlt inventory system")
        print("task 3 secure retrieval demo")
        print("==============================================")
        print("1. submit query and run secure retrieval workflow")
        print("2. demonstrate tampered query result rejection")
        print("3. exit")

        choice = input("\nselect an option: ").strip()

        if choice == "1":
            run_valid_query_workflow(
                pkg_keys,
                procurement_keys,
                inventory_params,
                inventory_databases
            )

        elif choice == "2":
            run_tampered_result_test(pkg_keys, inventory_params)

        elif choice == "3":
            print("\nexiting task 3 demo.")
            break

        else:
            print("\ninvalid option, choose 1, 2, or 3")


if __name__ == "__main__":
    main()