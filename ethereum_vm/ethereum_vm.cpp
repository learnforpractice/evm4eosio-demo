#include <eosio/print.hpp>
#include <eosio/name.hpp>
#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/singleton.hpp>
#include <eosio/fixed_bytes.hpp>
#include "eth_account.hpp"

using namespace eosio;
using namespace std;

#define MAIN_TOKEN_NAME "EOS"

__attribute__((eosio_wasm_import))
extern "C" int evm_execute(const char *raw_trx, size_t raw_trx_size, const char *sender_address, size_t sender_address_size);

__attribute__((eosio_wasm_import))
extern "C" int evm_get_account_id(uint64_t account, const char* arbitrary_string, size_t arbitrary_string_size, char* hash, size_t hash_size);

template<typename T>
T unpack_args() {
    size_t raw_args_size = action_data_size();
    check(raw_args_size > 0, "bad args");
    vector<char> raw_args(raw_args_size);
    read_action_data(raw_args.data(), raw_args_size);
    T rec = eosio::unpack<T>(raw_args);
    return rec;
}

struct transfer {
    name from;
    name to;
    asset quantity;
    string memo;
    EOSLIB_SERIALIZE( transfer, (from)(to)(quantity)(memo) )
};

struct addrinfo {
    uint64_t nonce;
    asset balance;
    EOSLIB_SERIALIZE( addrinfo, (nonce)(balance) )
};

struct create {
    name account;
    string text;
    EOSLIB_SERIALIZE( create, (account)(text) )
};

struct withdraw {
    name account;
    asset amount;
    EOSLIB_SERIALIZE( withdraw, (account)(amount) )
};

struct raw {
    vector<char> trx;
    vector<char> sender;
    EOSLIB_SERIALIZE( raw, (trx)(sender) )
};

extern "C" {
    __attribute__((eosio_wasm_import))
    void set_action_return_value(const char *packed_blob, size_t size);

    void apply( uint64_t receiver, uint64_t code, uint64_t action ) {
        name _self(receiver);
        if (receiver == code) {
            if (action == "create"_n.value) {
                eth_address address;
                auto v = unpack_action_data<create>();
                require_auth(v.account);
                evm_get_account_id(v.account.value, v.text.c_str(), v.text.size(), (char *)address.data(), 20);
                eosio::printhex(address.data(), address.size());
                bool ret = eth_account_bind_address_to_creator(address, v.account.value);
                eosio::check(ret, "eth address already been activated");
                set_action_return_value((char *)address.data(), 20);
//                eth_account_set_balance(address, 0);
            } else if (action == "activate"_n.value) {
                eth_address address;
                auto v = unpack_action_data<vector<char>>();
                check(v.size() == 20, "bad address");
                memcpy(address.data(), v.data(), address.size());

                bool ret = eth_account_create(address);
                eosio::check(ret, "eth address already been activated");
//                eth_account_set_balance(address, 0);
            } else if (action == "raw"_n.value) {
                auto ret = unpack_action_data<raw>();
                eth_address address;
                memcpy(address.data(), ret.sender.data(), 20);
                evm_execute(ret.trx.data(), ret.trx.size(), ret.sender.data(), ret.sender.size());
            } else if (action == "getaddrinfo"_n.value) {
                eth_address address;
                int32_t nonce;
                int64_t ram_quota;
                int64_t amount;
                
                auto v = unpack_action_data<vector<char>>();
                check(v.size() == 20, "bad address");
                memcpy(address.data(), v.data(), address.size());
                
                uint64_t index = eth_account_get_info(address, &nonce, &ram_quota, &amount);
                check(index > 0, "eth address not found!");
                
                addrinfo info;
                info.nonce = nonce;
                info.balance.amount = amount;
                info.balance.symbol = symbol(ETH_ASSET_SYMBOL, 4);
                auto packed_info = eosio::pack<addrinfo>(info);
                set_action_return_value(packed_info.data(), packed_info.size());
            } else if (action == "withdraw"_n.value) {
                auto v = unpack_action_data<withdraw>();
                require_auth(v.account);
                
                eth_address address;
                bool ret = eth_account_find_address_by_creator(v.account.value, address);
                check(ret, "eth address not found!");
{
                asset a(0, symbol(ETH_ASSET_SYMBOL, 4));
                a.amount = eth_account_get_balance(address);
                eosio::print(a.symbol, v.amount.symbol);
                a -= v.amount;
                eth_account_set_balance(address, a.amount);
}
                struct action a;
                a.account = "eosio.token"_n;
                a.name = "transfer"_n;
                a.authorization.push_back({name(receiver), "active"_n});


                transfer t;
                t.from = name(receiver);
                t.to = v.account;
                t.quantity.amount = v.amount.amount;
                t.quantity.symbol = symbol(MAIN_TOKEN_NAME, 4);
                t.memo = "withdraw";
                a.data = eosio::pack<transfer>(t);
                a.send();
            } else if (action == "setchainid"_n.value) {
                int32_t chain_id = unpack_action_data<int32_t>();
                eth_set_chain_id(chain_id);
            }
        } else {
            if (action != "transfer"_n.value) {
                return; 
            }
            
            if (name(code) == "eosio.token"_n && name(action) == "transfer"_n) {
                auto t = unpack_action_data<transfer>();
                if (t.to == _self && t.quantity.symbol == symbol(MAIN_TOKEN_NAME, 4) && t.memo == "deposit") {
                    eth_address address;
                    bool ret = eth_account_find_address_by_creator(t.from.value, address);
                    check(ret, "eth address not bind to an EOS account!");
                    asset a(0, symbol(MAIN_TOKEN_NAME, 4));
                    a.amount = eth_account_get_balance(address);
                    eosio::print("+++++eth amount:", a.amount);
                    a += t.quantity;
                    eth_account_set_balance(address, a.amount);
                }
            }            
        }
    }
}    
#include "eth_account.cpp"