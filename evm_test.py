import evm
from pyeoskit import eosapi

def normalize_address(address):
    if address[:2] == '0x':
        address = address[:2]
    return address.lower()

class EthAccount():

    def __init__(self, contract_account):
        self.contract_account = contract_account

#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;
# struct [[eosio::table]] accountcounter {
#     uint64_t                        count;
#     int32_t                         chain_id;
#     EOSLIB_SERIALIZE( accountcounter, (count)(chain_id) )
# };
# typedef eosio::singleton< "global"_n, accountcounter >   account_counter;
    def get_eth_address_count(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global', '', '', '', 1)
        return ret['rows'][0]['count']

    def get_eth_chain_id(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global', '', '', '', 1)
        return ret['rows'][0]['chainid']

#key256_acounter
#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;
# struct [[eosio::table]] key256counter {
#     uint64_t                        count;
#     EOSLIB_SERIALIZE( key256counter, (count) )
# };
#typedef eosio::singleton< "global2"_n, key256counter >   key256_counter;
    def get_total_keys(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global2', '', '', '', 1)
        if ret['rows']:
            return ret['rows'][0]['count']
        return 0

#table ethaccount

#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;

# struct [[eosio::table]] ethaccount {
#     uint64_t                        index;
#     uint64_t                        creator;
#     int32_t                         nonce;
#     std::vector<char>               address;
#     asset                           balance;
#     ethaccount() {
#         address.resize(SIZE_ADDRESS);
#     }
#     uint64_t primary_key() const { return index; }
#     checksum256 by_address() const {
#        auto ret = checksum256();//address;
#        memset(ret.data(), 0, sizeof(checksum256));
#        memcpy(ret.data(), address.data(), SIZE_ADDRESS);
#        return ret;
#     }

#     uint64_t by_creator() const {
#         return creator;
#     }

# typedef multi_index<"ethaccount"_n,
#                 ethaccount,
#                 indexed_by< "byaddress"_n, const_mem_fun<ethaccount, checksum256, &ethaccount::by_address> >,
#                 indexed_by< "bycreator"_n, const_mem_fun<ethaccount, uint64_t, &ethaccount::by_creator> > 
#                 > ethaccount_table;
    def get_address_info(self, address):
        address = normalize_address(address)
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'ethaccount', '', '', '', 100)
        rows = ret['rows']
        for row in rows:
            if row['address'] == address:
                return row
        return None

    def get_address_creator(self, address):
        row = self.get_address_info(address)
        if row:
            return row['creator']

    def get_address_index(self, address):
        row = self.get_address_info(address)
        if row:
            return row['index']

    def get_address_balance(self, address):
        row = self.get_address_info(address)
        if row:
            return row['balance']

    def get_address_nonce(self, address):
        row = self.get_address_info(address)
        if row:
            return row['nonce']

    #addressmap
    #     uint64_t code = current_receiver().value;
    #     uint64_t scope = code;
    #primary_index creator
    # struct [[eosio::table]] addressmap {
    #     uint64_t                        creator;
    #     std::vector<char>               address;
    #     uint64_t primary_key() const { return creator; }
    # }
    def get_account_binded_address(self, account):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'addressmap', account, '', '', 1)
        assert ret['rows'][0]['creator'] == account
        return ret['rows'][0]['address']

#table account_state
# uint64_t code = current_receiver().value;
# scope = creator
# struct [[eosio::table]] account_state {
#     uint64_t                        index;
#     checksum256                     key;
#     checksum256                     value;
#     uint64_t primary_key() const { return index; }
#     checksum256 by_key() const {
#        return key;
#     }
#     EOSLIB_SERIALIZE( account_state, (index)(key)(value) )
# };

# typedef multi_index<"accountstate"_n,
#                 account_state,
#                 indexed_by< "bykey"_n,
#                 const_mem_fun<account_state, checksum256, &account_state::by_key> > > account_state_table;

    def get_value(self, address, key):
        creator = self.get_address_creator(address)
        index = self.get_address_index(address)
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(True, self.contract_account, index, 'accountstate', '', '', '', 100)
        for row in ret['rows']:
            if row['key'] == key:
                return row['key']
        return None

    def get_code(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        if not row:
            return ''
        index = row['index']
        creator = row['creator']
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(True, self.contract_account, creator, 'ethcode', index, '', '', 1)
        if ret['rows']:
            return ret['rows'][0]['code']
        return ''

#     uint64_t code = current_receiver().value;
# scope = creator
# struct [[eosio::table]] ethcode {
#     uint64_t                        index;
#     std::vector<char>               address;
#     vector<char>                    code;
#     uint64_t primary_key() const { return index; }

# typedef multi_index<"ethcode"_n,
#                 ethcode,
#                 indexed_by< "byaddress"_n,
#                 const_mem_fun<ethcode, checksum256, &ethcode::by_address> > > ethcode_table;

