#include <stdio.h>
#include <time.h>
#include <rpc/rpc.h>
#include <iostream>
#include <fstream>
#include <map>
#include "essentials.h"

std::map<std::string, User_data_clt*> client_db;

#include "schema.h"
#define RMACHINE "localhost"

int main(int argc, char *argv[]){

	if (argc < 2){
		printf("Insufficient arguments\n");
		return -1;
	}

	/* variabila clientului */
	CLIENT *handle;

	handle=clnt_create(RMACHINE, PROGRAM, VERS, "tcp");			

	if(handle == NULL) {
		perror("");
		return -1;
	}
	std::string operation;
	std::ifstream Client_ops(argv[1]);
	while (getline(Client_ops, operation)) {
		size_t pos = operation.find(',');
		std::string ID = operation.substr(0, pos);
		operation.erase(0, pos + 1);
		pos = operation.find(',');
		std::string action = operation.substr(0, pos);
		operation.erase(0, pos + 1);
		std::string action_dependency = operation;
		bool nice = true;
		
		if(!action.compare("REQUEST")){
			if (client_db.find(ID) == client_db.end()){
				User_data_clt* aux = (User_data_clt*)calloc(1, sizeof(User_data_clt));
				client_db.emplace(ID, aux);
			}
			char* id_data = (char*)calloc(ID.length() + 1, sizeof(char));
			strcpy(id_data, ID.c_str());
			general_message* r = request_auth_1(&id_data, handle);
			if(r->type == 1){
				std::cout << "USER_NOT_FOUND\n";
			}
			else{
				char** new_token = approve_request_token_1(&(r->resp), handle);
				char* acc_token_data = (char *)calloc(strlen(id_data) + strlen(new_token[0]) + 4, sizeof(char));
				memcpy(acc_token_data, id_data, strlen(id_data));
				strcat(acc_token_data, ",");
				strcat(acc_token_data, new_token[0]);
				strcat(acc_token_data, ",");
				strcat(acc_token_data, action_dependency.c_str());
				general_message* res = request_acc_token_1(&acc_token_data, handle);
				if (res->type == 1){
					std::cout << "REQUEST_DENIED\n";
				}else{
					char* next_item = strstr(res->resp, ",");
					char* validity = NULL;
					*next_item = '\0';
					next_item++;

					if (!action_dependency.compare("1")){
						validity = strstr(next_item, ",");
						*validity = '\0';
						validity++;
					}
					std::map<std::string, User_data_clt*>::iterator it = client_db.find(ID);
					if(it != client_db.end()){
						it->second->general_token = res->resp;
						it->second->refresh_token = (action_dependency == "1") ? next_item : NULL;
						sscanf((!action_dependency.compare("1")) ? validity : next_item, "%d", &(it->second->remained_ops));
						std::cout << r->resp << " -> " << res->resp;
						if (!action_dependency.compare("1"))
							std::cout << "," << next_item;
						std::cout << "\n";
					}
				}
			}
		}
		else {
			std::map<std::string, User_data_clt*>::iterator get_acc_token = client_db.find(ID);
			if((get_acc_token != client_db.end()) && get_acc_token->second->remained_ops == 0 && get_acc_token->second->refresh_token){
				char* acc_token_data = (char *)calloc(ID.length() + strlen(get_acc_token->second->refresh_token) + 4, sizeof(char));
				memcpy(acc_token_data, ID.c_str(), ID.length());
				strcat(acc_token_data, ",");
				strcat(acc_token_data, get_acc_token->second->refresh_token);
				strcat(acc_token_data, ",");
				strcat(acc_token_data, "2");
				general_message* res = request_acc_token_1(&acc_token_data, handle);
				char* next_item = strstr(res->resp, ",");
				char* validity = NULL;
				*next_item = '\0';
				next_item++;
				validity = strstr(next_item, ",");
				*validity = '\0';
				validity++;
				std::map<std::string, User_data_clt*>::iterator it = client_db.find(ID);
				if(it != client_db.end()){
					it->second->general_token = res->resp;
					it->second->refresh_token = next_item;
					sscanf(validity, "%d", &(it->second->remained_ops));
				}
			}
			char* data_to_send = (char*)calloc(((get_acc_token != client_db.end()) ? strlen(get_acc_token->second->general_token): 0) + action.length() + action_dependency.length() + 3, sizeof(char));
			strncpy(data_to_send, action.c_str(), action.length());
			strcat(data_to_send, ",");
			strcat(data_to_send, action_dependency.c_str());
			strcat(data_to_send, ",");
			if(get_acc_token != client_db.end())
				strcat(data_to_send, get_acc_token->second->general_token);
			int *err_code = validate_delegated_action_1(&data_to_send, handle);
			switch (*err_code)
			{
			case 0:
				(get_acc_token->second->remained_ops)--;
				std::cout << "PERMISSION_GRANTED\n";
				break;
			case 1:
				std::cout << "PERMISSION_DENIED\n";
				break;
			case 2:
				std::cout << "TOKEN_EXPIRED\n";
				break;
			case 3:
				(get_acc_token->second->remained_ops)--;
				std::cout << "RESOURCE_NOT_FOUND\n";
				break;
			case 4:
				(get_acc_token->second->remained_ops)--;
				std::cout << "OPERATION_NOT_PERMITTED\n";
				break;
			default:
				std::cout << "INTERNAL SERVER ERROR\n";
				break;
			}
		}
		
	}

	return 0;
}
