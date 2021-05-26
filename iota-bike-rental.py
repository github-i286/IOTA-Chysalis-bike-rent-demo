#!/usr/bin/python
import os
import hashlib
import random
import json
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from datetime import datetime, date, time, timezone, timedelta

from secret_seed import own_node_url, seedAccountA, seedAccountB, fire_fly_return_address, private_key_value_text_bike_operator, public_key_value_text_bike_operator, \
    private_key_value_text_bike_user, public_key_value_text_bike_user 

import iota_client

def check_health(client):
    get_info = client.get_info()
    # you may test the same API with curl: enter on a command line
    #   curl 'https://chrysalis-nodes.iota.org/api/v1/info' 

    if get_info['nodeinfo']['is_healthy']:
        is_healthy = 'healthy'
    else:
        is_healthy = 'not in sync'
    milestones_in_database = get_info['nodeinfo']['latest_milestone_index'] - get_info['nodeinfo']['pruning_index']
    milestone = client.get_milestone(get_info['nodeinfo']['pruning_index']+1000)
    timestampMilestone = datetime.fromtimestamp(milestone['timestamp'], tz=timezone.utc)
    if get_info['url'] != own_node_url:
        node_name = ' ' + get_info['url']
    else:
        node_name = ''
    print('The node%s on the network %s is %s and spans over %s milestones in database with a message history back to %s' 
        %(node_name, get_info['nodeinfo']['network_id'], is_healthy, "{:,}".format(milestones_in_database), timestampMilestone))

def get_balance(client, seed:str, account_index:int = 0):
    balance = client.get_balance(
        seed=seed,
        account_index=account_index,
        initial_address_index=0
    )
    return balance


def list_account_balance_and_addresses(client:str, seed:str, account_index:int = 0, number_addresses:int = 5, name:str = '') -> None:
    balance = get_balance (client, seed=seed, account_index=account_index)
    print("Balance for account %s on index %d: %s" %(name, account_index, "{:,}".format(balance)))        
    address_list = client.get_addresses(
        seed=seed,
        account_index=0,
        input_range_begin=0,
        input_range_end=number_addresses,
        get_all=True
    )
    addresses = []
    for address in address_list:
        addresses.append(address[0])
                
    address_balances = client.get_address_balances(addresses)
    i = 0
    for i in range(0,number_addresses):
        print("The %d address is %s with balance %s, change address is %s with balance %s" % (i, 
            address_list[i*2][0], "{:,}".format(address_balances[i*2]['balance']), 
            address_list[i*2+1][0], "{:,}".format(address_balances[i*2+1]['balance'])))


def create_data_only_message(client, index:str, data:str, wait_confirmation:bool = True):
    message = client.message(index=index, data=data.encode("utf8"))
    print("Posted a data message with message id: %s" % message['message_id'], end='', flush=True)
    if wait_confirmation:
        client.retry_until_included(message_id = message['message_id'])
        print(" - now confirmed")
    else:
        print('')
    return message


def sign_data(private_key: bytes, input:bytes) -> bytes:
    # create a private / public key pair
    curve = ec.SECP256R1()
    signature_algorithm = ec.ECDSA(hashes.SHA256())
    private_key = ec.derive_private_key(private_key, curve, default_backend())
    return private_key.sign(data=input, signature_algorithm=signature_algorithm)


def hast_string(input: str) -> bytes:
    hash_data = hashlib.sha256()
    hash_data.update(input.encode('utf-8'))
    return hash_data.hexdigest().encode()


def publish_free_bikes(client, free_bikes: int, deposit:int = 5_000_000) -> str: 
    timestamp = datetime.now(timezone.utc).isoformat()
    free_bike = {"version": "0.1", "free_bikes": free_bikes, "deposit": deposit, "timestamp": timestamp}
    free_bike_message = json.dumps(free_bike)

    hash = hast_string(free_bike_message)
    hash_signature = sign_data(private_key_value_text_bike_operator, hash)

    publish_message_object = {"free_bike": free_bike, "signature": hash_signature.hex()}
    publish_message = json.dumps(publish_message_object)
    #print(publish_message) 
    index = 'Bike Rental ' + timestamp[0:10]
    #print(index)
    return create_data_only_message(client, index=index, data = publish_message, wait_confirmation=True)

def get_free_bikes(client) -> tuple:
    index = 'Bike Rental ' + datetime.now(timezone.utc).isoformat()[0:10]
    messages_ids = client.get_message_index(index)
    if len(messages_ids) == 0:
        print("No bikes to rent today so far") 

    timestamp_latest_message = datetime(2000,1,1, tzinfo=timezone.utc)
    free_bikes_latest_message = 0
    requried_deposit_latest_message = 0

    for message_id in messages_ids:
        #print('Message ID: %s' % message_id)
        message = client.get_message_data(message_id)
        publish_message_object = json.loads(bytearray(message['payload']['indexation'][0]['data']).decode("utf-8"))

        if 'free_bike' not in publish_message_object:
            continue
        if 'signature' not in publish_message_object:
            continue

        free_bike = publish_message_object['free_bike']
        free_bike_message = json.dumps(free_bike)
        hash_data = hashlib.sha256()
        hash_data.update(free_bike_message.encode('utf-8'))
        hash = hash_data.hexdigest().encode()
        #print(free_bike, hash)

        signature = bytes.fromhex(publish_message_object['signature'])
        #print(publish_message_object['signature'])
        #print(signature)
        signature_algorithm = ec.ECDSA(hashes.SHA256())
        public_key = public_key_value_text_bike_operator()

        #verify with throw an error when signature does not match
        try:
            public_key.verify(signature, hash, signature_algorithm)
        except:
            # print("Signature check failed")
            continue
            
        # Check timestamp plausibility
        if 'timestamp' not in free_bike:
            continue
        ts = datetime.strptime(free_bike['timestamp'][0:19], "%Y-%m-%dT%H:%M:%S")
        timestamp = datetime(ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second, tzinfo=timezone.utc)

        
        messageMetaData = client.get_message_metadata(message_id)
        if 'referenced_by_milestone_index' not in messageMetaData:
            continue # not yet confirmed 
        milestoneIndex = messageMetaData['referenced_by_milestone_index']
        milestone = client.get_milestone(milestoneIndex)
        timestampMilestone = datetime.fromtimestamp(milestone['timestamp'], tz=timezone.utc)

        if timestampMilestone >= timestamp:                                      
            timeDelta = timestampMilestone - timestamp
        else:
            timeDelta = timestamp - timestampMilestone
        if timeDelta.seconds > 300: # more than 5 minutes
            # print("Timestamp too far from milestone")
            continue

        #print(free_bike, hash)
        if 'version' not in free_bike:
            continue
        if free_bike['version'] != "0.1":
            continue
        if 'free_bikes' not in free_bike:
            continue
        if 'deposit' not in free_bike:
            continue
        requried_deposit_latest_message = int(free_bike['deposit'])
        free_bikes = int((free_bike['free_bikes']))
        if timestamp_latest_message < timestamp:
            timestamp_latest_message = timestamp
            free_bikes_latest_message = free_bikes

    return free_bikes_latest_message, requried_deposit_latest_message, timestamp_latest_message


def send_value(client, seed:str, account_index:int = 0, address:str = "", value:int = 0, index:str = None, data:bytes = None, wait_confirmation:bool = True):
    message = client.message(
        seed=seed,
        outputs=[
            {
                'address': address,
                'amount': value,
            }
        ],
        index=index,
        data= data
    )
    print("Send %d IOTAs to %s with index: %s and message: %s" %(value, address, index, message['message_id']), end='', flush=True)
    if wait_confirmation:
        client.retry_until_included(message_id = message['message_id'])
        print(" - now confirmed")
    else:
        print('')
    return message


def request_to_rent_a_bike(client, seed:str, account_index:int, provider_address:str, deposit:int, public_key: ec.EllipticCurvePublicKey ) -> str:
    balance = client.get_balance(
        seed=seed,
        account_index=account_index,
        initial_address_index=0
        )
    # check balance. it must be:
    #   either exact xMi
    #   or x+1Mi or greater. Balance between xMi and x+1Mi woudl create a dust change that is not allwed here
    if balance < deposit or (balance > deposit and balance < deposit + 1_000_000):
        print("Insufficiant balance to rent a bike: %s" % "{:,}".format(balance))
        return

    message_index = "Rent a bike"
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    refund_address = client.get_addresses(seed=seed, account_index=account_index,input_range_begin=0,input_range_end=1, get_all=False)[0][0]
    
    bike_request_object = {'version': '0.1',
        'refund_address': refund_address,
        'public_key': str(serialized_public)}
    # print(bike_request_object)
    message = json.dumps(bike_request_object).encode('utf-8')

    send_value(client, seed=seed, account_index=0, address=provider_address, value= 5_000_000, index=message_index, data=message, wait_confirmation=True)
    return

def find_bike_rental_request(client, seed:str, account_index=0, rental_address_index=0, minimum_deposit=5_000_000) -> tuple:
    validated_outputs = []
    validated_pubic_keys = []
    validated_transaction_ids = []
    validated_transaction_indexes = []
    valudated_refund_addresses = []

    rental_address = client.get_addresses(seed=seed, account_index=account_index,input_range_begin=rental_address_index,input_range_end=rental_address_index+1, get_all=False)[rental_address_index][0]
    outputs = client.get_address_outputs(rental_address, {'include_spent': False})
    #print(outputs)
    for output in outputs:
        # print('Output: %s' % output)
        transaction_id = "".join(f"{i:0>2x}" for i in output["transaction_id"])
        transaction_index = output["index"]
        # Note: 4 bytes index id '0' needs to be added to the transaction id
        output_detail = client.get_output(transaction_id + f"{0:0>4x}")
        message = client.get_message_data(output_detail['message_id'])
        essence = message['payload']['transaction'][0]['essence']
        if 'payload' not in essence:
            continue
        if 'indexation' not in essence['payload']:
            continue
        if 'index' not in essence['payload']['indexation'][0]:
            continue
        if 'data' not in essence['payload']['indexation'][0]:
            continue
        index = essence['payload']['indexation'][0]['index']
        data = bytearray(essence['payload']['indexation'][0]['data']).decode("utf-8")
        bike_request_object = json.loads(data)

        # print('bike_request_object = %s' % bike_request_object)

        if 'version' not in bike_request_object:
            # print('No version')
            continue
        if bike_request_object['version'] != '0.1':
            # print('Version does not match: %s' % bike_request_object['version'])
            continue
        if 'refund_address' not in bike_request_object:
            # print('No refund_address')
            continue
        refund_address = bike_request_object['refund_address']
        if not client.is_address_valid(refund_address):
            # print('refund_address: %s is not valid' % refund_address)
            continue

        if 'public_key' not in bike_request_object:
            # print('No public_key')
            continue
        #print("Public as on tangle: %s" % bike_request_object['public_key'].replace('\\n', '\n'))
        public_key_serialized = bytes(bike_request_object['public_key'][2:-1].replace('\\n', '\n').encode())
        if not bool(output_detail['is_spent']):
            if 'signature_locked_single' in output_detail['output']:
                validated_outputs.append(output_detail)
                validated_pubic_keys.append(public_key_serialized)
                validated_transaction_ids.append(transaction_id)
                validated_transaction_indexes.append(transaction_index)
                valudated_refund_addresses.append(refund_address)
    return validated_outputs, validated_pubic_keys, validated_transaction_ids, validated_transaction_indexes, valudated_refund_addresses


def release_bike(client, seed:str, account_index=0, rental_address_index=0, minimum_deposit=5_000_000) -> str:
    validated_outputs, validated_pubic_keys, validated_transaction_ids, validated_transaction_indexes, valudated_refund_addresses = \
        find_bike_rental_request(client, seed=seed, account_index=account_index, rental_address_index=rental_address_index)
    result_index = -1
    for output_detail in validated_outputs:
        result_index = result_index + 1

        amount = int(output_detail['output']['signature_locked_single']['amount'])
        if amount < minimum_deposit:
            message = client.message(
                seed=seed,
                inputs=[{'transaction_id': validated_transaction_ids[result_index], 'index': validated_transaction_indexes[result_index]}],
                outputs=[
                    {
                        'address': valudated_refund_addresses[result_index],
                        'amount': amount,
                    }
                ],
                index="Rent a bike rejected")
            print("Rejected bike hire due too low deposit, returned fund, message id: %s " % message, end='', flush=True)
            client.retry_until_included(message_id = message['message_id'])
            print("  - now confirmed")
            continue

        # TODO: Check if a confiormation alrady has been send

        bike_rental_confirmation = {'address': valudated_refund_addresses[result_index], 'transaction_id': validated_transaction_ids[result_index], 'status': 'OK'}
        bike_rental_confirmation_message = json.dumps(bike_rental_confirmation)

        hash = hast_string(bike_rental_confirmation_message)
        hash_signature = sign_data(private_key_value_text_bike_operator, hash)                
        publish_message_object = {"bike_rental_confirmation": bike_rental_confirmation_message, "signature": hash_signature.hex()}
        publish_message = json.dumps(publish_message_object)
        message = create_data_only_message(client, index='Bike rental confirmation', data = publish_message, wait_confirmation=True)

    return None


def is_dust_enabled(client, address:str) -> bool:
    address_balance_pair = client.get_address_balances([address])[0]
    if address_balance_pair['dust_allowed']:
        return True
    return False


def create_dust_allowed_address(client, seed:str, account_index:int = 0, dust_address:str = "", number_of_dust_transactions:int = 10)-> str:
    if number_of_dust_transactions < 10:
        print("Value of possible dust transactions as %d to create a dust enabled account is too low" % number_of_dust_transactions)
        return ""
    value = 100_000 * number_of_dust_transactions
    message = client.message(
        seed=seed,
        dust_allowance_outputs=[
            {
                'address': dust_address,
                'amount': value,
            }
        ]
    )
    print("Dust is now allowed for %s" % dust_address, end='', flush=True)
    client.retry_until_included(message_id = message['message_id'])
    print(" - now confirmed")
    return message['message_id']


def return_bike(client, seed:str, account_index, public_key:ec.EllipticCurvePublicKey, time_used:timedelta, 
         address_operator_charge:str, address_agent_charge:str, address_insurance_charge:str) ->str:
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    validated_outputs, validated_pubic_keys, validated_transaction_ids, validated_transaction_indexes, valudated_refund_addresses = \
        find_bike_rental_request(client, seed=seed, account_index=account_index, rental_address_index=rental_address_index)
    result_index = -1
    for output_detail in validated_outputs:
        # print("Found one bike request: %s" % output_detail)
        result_index = result_index + 1

        if validated_pubic_keys[result_index] == serialized_public_key:
            amount = int(output_detail['output']['signature_locked_single']['amount'])
            # print("Amount to split: %s" % '{:,}'.format(amount))

            bike_charge  = int(1_000_000 + time_used.total_seconds() * 100_000 / 3600)  # base + hourly fee
            insurance_charge = int(time_used.total_seconds() * 50_000 / 3600)  # hourly fee insurance
            agent_charge = int(200_000 + time_used.total_seconds() * 30_000 / 3600) # base + hourly fee
            total_return = amount - bike_charge - insurance_charge - agent_charge

            # just the unlikley case we have not enough deposit
            if total_return < 1_000_000:    # we need at least 1Mi to return, or nothing
                agent_charge = agent_charge + total_return
                total_return = 0
            if agent_charge < 0:
                bike_charge = bike_charge + agent_charge
                agent_charge = 0
            if bike_charge < 0:
                insurance_charge = insurance_charge + bike_charge
                bike_charge = 0

            outputs = []
            if total_return > 0:
                outputs.append({
                            'address': valudated_refund_addresses[result_index],
                            'amount': total_return,
                        })
            if insurance_charge > 0:
                if insurance_charge >= 1_000_000 or is_dust_enabled(client, address_insurance_charge):  
                    outputs.append({
                                'address': address_insurance_charge,
                                'amount': insurance_charge,
                            })
                else:
                    insurance_charge = 0 
            if agent_charge > 0:
                if agent_charge >= 1_000_000 or is_dust_enabled(client, address_agent_charge):  
                    outputs.append({
                                'address': address_agent_charge,
                                'amount': agent_charge,
                            })
                else:
                    agent_charge = 0
            if bike_charge > 0:
                if bike_charge >= 1_000_000 or is_dust_enabled(client, address_operator_charge):  
                    outputs.append({
                                'address': address_operator_charge,
                                'amount': bike_charge,
                            })
                else:
                    bike_charge = 0
            input = {'transaction_id': validated_transaction_ids[result_index], 'index': validated_transaction_indexes[result_index]}
            # print("Output: %s", outputs)

            message = client.message(
                seed=seed,
                inputs=[input],
                outputs=outputs,
                index="Rent a bike return")
            print("Calculated fees and closed the deal: insurance: %s, agent: %s, bike operator: %s, return user: %s, message id: %s " % 
                ("{:,}".format(insurance_charge),
                    "{:,}".format(agent_charge),
                    "{:,}".format(bike_charge),
                    "{:,}".format(total_return),
                    message['message_id'] 
                ), 
                end='', flush=True)
            client.retry_until_included(message_id = message['message_id'])
            print(" - now confirmed")
            return message

    return None


def send_back_funds_to_firefly_account(client, seed:str, account_index:int = 0, value:int = 0) -> str:
    # Send the funds back to FireFly Wallet
    if value == 0:
        value = get_balance(client, seed, account_index)
    if value >= 1_000_000:  
        message = send_value (client, seed=seed, account_index=account_index, address=fire_fly_return_address, value=value, index='back firefly', wait_confirmation=True)
        return message
    else:
        return None

# consolidate fractional UTXOfor this account into a single UTXO to avoid dust change in transactions
def consolidate_outputs(client, seed:str, account_index:int = 0):
    balance = get_balance(client, seed, account_index)
    if balance > 1_000_000:
        # end all balance to a single address on position 0
        address = client.get_addresses(seed=seed, account_index=0, input_range_begin=0, input_range_end=1, get_all=False)[0][0]
        send_value(client, seed=seed, account_index=account_index, address=address, value=balance, wait_confirmation=True)
    return


if __name__ == '__main__':

    # make sure you have anough IOTAs in Accoutn A to start with. For example, assigned to the frist address of Account A 20 Mis
    # you can send all funds back your FireFly account configuired in secret_seed.py and set below "do_send_back_tofirefly = True"

    # enable test cases
    use_own_node = True
    hold_on_steps = True
    list_addresses_account_a = True
    list_addresses_account_b = True
    do_allow_dust_addresses = True
    do_publish_free_bikes = True
    do_get_free_bikes = True
    do_request_rent_a_bike = True
    do_release_bike = True
    do_return_bike = True
    do_reset_funds = False
    do_send_back_tofirefly = False

    if use_own_node:
        client = iota_client.Client(nodes_name_password=[[own_node_url]], local_pow=True)
    else:
        client = iota_client.Client(nodes_name_password=[["https://chrysalis-nodes.iota.org"]], local_pow=True)
    check_health(client)
    if hold_on_steps: input('Press enter to continue')

    rental_address_index = 0
    rental_address = client.get_addresses(seed=seedAccountB, account_index=0,input_range_begin=rental_address_index,input_range_end=rental_address_index+1, get_all=False)[rental_address_index][0]
    minimum_deposit = 5_000_000
    # print('Rental address: %s' % rental_address)

    service_addresses = client.get_addresses(seed=seedAccountB, account_index=0,input_range_begin=2,input_range_end=5, get_all=False)
    agent_address = service_addresses[0][0]
    bike_operator_address = service_addresses[1][0]
    insurance_address = service_addresses[2][0]

    if list_addresses_account_a:
        print()
        list_account_balance_and_addresses(client, seed=seedAccountA, account_index=0, number_addresses=3, name="Account A (customer)")

    if list_addresses_account_b:
        print()
        list_account_balance_and_addresses(client, seed=seedAccountB, account_index=0, number_addresses=6, name="Account B (agent and bike operator)")
        if hold_on_steps: input('Press enter to continue')

    # enable dust on addresses
    if do_allow_dust_addresses:
        if not is_dust_enabled(client, agent_address):
            create_dust_allowed_address(client, seedAccountA, account_index=0, dust_address=agent_address, number_of_dust_transactions=10)
        if not is_dust_enabled(client, bike_operator_address):
            create_dust_allowed_address(client, seedAccountA, account_index=0, dust_address=bike_operator_address, number_of_dust_transactions=10)
        if not is_dust_enabled(client, insurance_address):
            create_dust_allowed_address(client, seedAccountA, account_index=0, dust_address=insurance_address, number_of_dust_transactions=10)
        if hold_on_steps: input('Press enter to continue')

    # publish a free bike message
    if do_publish_free_bikes:
        free_bikes = random.randrange(10,50)
        message = publish_free_bikes(client, free_bikes, deposit=minimum_deposit)
        print('Published that we have %d bikes to rent with message: %s' % (free_bikes, message['message_id']))
        if hold_on_steps: input('Press enter to continue')
        
    if do_get_free_bikes or do_request_rent_a_bike:
        free_bikes,  minimum_deposit, timestamp_published = get_free_bikes(client)

        if free_bikes <= 0:
            print("Sorry, no bikes available")
        else:     
            print("We have %d bikes to rent, last published on %s" % (free_bikes, timestamp_published.astimezone()))
        
            if do_request_rent_a_bike:
                consolidate_outputs(client=client, seed=seedAccountA, account_index=0)
                request_to_rent_a_bike(client=client, seed=seedAccountA, account_index=0,
                    provider_address= rental_address, deposit=minimum_deposit, public_key=public_key_value_text_bike_user())
        if hold_on_steps: input('Press enter to continue')

    if do_release_bike:
        release_bike(client, seedAccountB, account_index=0, rental_address_index=rental_address_index, minimum_deposit=minimum_deposit)
        if hold_on_steps: input('Press enter to continue')
    
    if do_return_bike:
        message = return_bike (client, seed=seedAccountB, account_index=0, 
            public_key=public_key_value_text_bike_user(), time_used= timedelta(hours=random.randrange(0, 3), minutes=random.randrange(0, 60)),
                address_agent_charge= agent_address, address_insurance_charge = insurance_address, address_operator_charge = bike_operator_address)
        if True is not None:
            print("Bike returned")
        else:
            print("No bike rental open")
        if hold_on_steps: input('Press enter to continue')

    if do_reset_funds:
        reset_address = client.get_addresses(seed=seedAccountA, account_index=0,input_range_begin=0,input_range_end=1, get_all=False)[0][0]
        balance = get_balance (client, seed=seedAccountB, account_index=0)
        if balance > 0:
            if balance < 1_000_000:
                print("Cannot sent dust back to A")
            else:
                send_value(client, seed=seedAccountB, account_index=0, address=reset_address, value=balance, wait_confirmation=True)

        # also consolidate all UTXOs on A into one UTXO to avoid possible dust
        balance = get_balance (client, seed=seedAccountA, account_index=0)
        if balance > 0:
            if balance < 1_000_000:
                print("Cannot sent dust around")
            else:
                send_value(client, seed=seedAccountA, account_index=0, address=reset_address, value=balance, wait_confirmation=True)
        if hold_on_steps: input('Press enter to continue')
        
    if do_send_back_tofirefly:
        send_back_funds_to_firefly_account(client, seed = seedAccountA, account_index = 0)
        send_back_funds_to_firefly_account(client, seed = seedAccountB, account_index = 0)
        if hold_on_steps: input('Press enter to continue')

    if list_addresses_account_a:
        print()
        list_account_balance_and_addresses(client, seed=seedAccountA, account_index=0, number_addresses=3, name="Account A (customer)")

    if list_addresses_account_b:
        print()
        list_account_balance_and_addresses(client, seed=seedAccountB, account_index=0, number_addresses=6, name="Account B (agent and bike operator)")

