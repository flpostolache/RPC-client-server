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
	// Citim din fisierul client
	std::ifstream Client_ops(argv[1]);
	while (getline(Client_ops, operation)) {

		// Separam argumentele intre ele
		size_t pos = operation.find(',');
		std::string ID = operation.substr(0, pos);
		operation.erase(0, pos + 1);
		pos = operation.find(',');
		std::string action = operation.substr(0, pos);
		operation.erase(0, pos + 1);
		std::string action_dependency = operation;
		
		// Daca actiunea dorita este un request.
		if(!action.compare("REQUEST")){
			
			// Vedem daca acest ID a mai facut deja un request. Daca nu,
			//facem o noua intrare in structura de useri din client.
			if (client_db.find(ID) == client_db.end()){
				User_data_clt* aux = (User_data_clt*)calloc(1, sizeof(User_data_clt));
				client_db.emplace(ID, aux);
			}

			// Cerem un request token pentru ID-ul citit
			char* id_data = (char*)calloc(ID.length() + 1, sizeof(char));
			strcpy(id_data, ID.c_str());
			general_message* r = request_auth_1(&id_data, handle);

			// Daca raspunsul are tipul 1 inseamna ca ID-ul nu este cunoscut de
			//server. Intoarce USER_NOT_FOUND.
			if(r->type == 1){
				std::cout << "USER_NOT_FOUND\n";
				continue;
			}
			// Send the request token for approval.
			char** new_token = approve_request_token_1(&(r->resp), handle);
			// Copiem datele necesare pentru a primi un access token
			//(ID, token, 0 sau 1)
			char* acc_token_data = (char *)calloc(strlen(id_data) + strlen(new_token[0]) + 4, sizeof(char));
			memcpy(acc_token_data, id_data, strlen(id_data));
			strcat(acc_token_data, ",");
			strcat(acc_token_data, new_token[0]);
			strcat(acc_token_data, ",");
			strcat(acc_token_data, action_dependency.c_str());
			general_message* res = request_acc_token_1(&acc_token_data, handle);
			// Daca raspunsul are tipul 1 inseamna ca tokenul nu este semnat
			//afisam REQUEST_DENIED.
			if (res->type == 1){
				std::cout << "REQUEST_DENIED\n";
				continue;
			}
			if (res->type == -1){
				std::cout << "INTERNAL SERVER ERROR\n";
				continue;
			}
			// Extragem jetonul de refresh sau numarul de operatii
			//permise in functie de caz (daca requestul are 1 sau 0)
			char* next_item = strstr(res->resp, ",");
			char* validity = NULL;
			*next_item = '\0';
			next_item++;
			if (!action_dependency.compare("1")){
				// Daca requestul se face cu parametrul 1,
				//mai trebuie extras numarul de operatii permise
				//cu access tokenul intors
				validity = strstr(next_item, ",");
				*validity = '\0';
				validity++;
			}
			// Cautam ID-ul care a facut request-ul in baza de date
			//a clientului.
			std::map<std::string, User_data_clt*>::iterator it = client_db.find(ID);
			if(it != client_db.end()){
				// Atasam datele returnate in baza de date a clinetului
				//dupa obtinerea unui token de acces.
				it->second->general_token = res->resp;
				it->second->refresh_token = (action_dependency == "1") ? next_item : NULL;
				sscanf((!action_dependency.compare("1")) ? validity : next_item, "%d", &(it->second->remained_ops));
				std::cout << r->resp << " -> " << res->resp;
				if (!action_dependency.compare("1"))
					std::cout << "," << next_item;
				std::cout << "\n";
			}
		}
		else {
			static const std::map<int, std::string> error_types = {	
													{0, "PERMISSION_GRANTED\n"},
													{1, "PERMISSION_DENIED\n"},
													{2, "TOKEN_EXPIRED\n"},
													{3, "RESOURCE_NOT_FOUND\n"},
													{4, "OPERATION_NOT_PERMITTED\n"}
													};

			//	Se doreste a se face o operatie diferita de un request. Cauta 
			//ID-ul care doreste sa faca aceasta operatie.
			std::map<std::string, User_data_clt*>::iterator get_acc_token = client_db.find(ID);

			// Daca ID-ul exista in baza de date a clientului, nu mai are 
			//operatii si are refresh token, trebuie sa ii inlocuim access
			//token-ul cu unul nou.
			if((get_acc_token != client_db.end()) && get_acc_token->second->remained_ops == 0 && get_acc_token->second->refresh_token){
				char* acc_token_data = (char *)calloc(ID.length() + strlen(get_acc_token->second->refresh_token) + 4, sizeof(char));
				memcpy(acc_token_data, ID.c_str(), ID.length());
				strcat(acc_token_data, ",");
				strcat(acc_token_data, get_acc_token->second->refresh_token);
				strcat(acc_token_data, ",");
				strcat(acc_token_data, "2");
				// Cerem un token nou de access. Parametrii sunt aceiasi ca cei
				//de mai sus. Tokenul de request este schimbat cu cel de refresh.
				general_message* res = request_acc_token_1(&acc_token_data, handle);

				// Extract refresh and access token.
				char* next_item = strstr(res->resp, ",");
				char* validity = NULL;
				*next_item = '\0';
				next_item++;
				validity = strstr(next_item, ",");
				*validity = '\0';
				validity++;
				get_acc_token->second->general_token = res->resp;
				get_acc_token->second->refresh_token = next_item;
				sscanf(validity, "%d", &(get_acc_token->second->remained_ops));
			}
			
			// Punem actiunea, resursa ce trebuie prelucrata si token-ul de 
			//acces.
			char* data_to_send = (char*)calloc(((get_acc_token != client_db.end()) ? strlen(get_acc_token->second->general_token): 0) + action.length() + action_dependency.length() + 3, sizeof(char));

			strncpy(data_to_send, action.c_str(), action.length());
			strcat(data_to_send, ",");
			strcat(data_to_send, action_dependency.c_str());
			strcat(data_to_send, ",");
			if(get_acc_token != client_db.end())
				strcat(data_to_send, get_acc_token->second->general_token);
			int *err_code = validate_delegated_action_1(&data_to_send, handle);
			// Vedem ce cod de eroare este intors si printez eroarea
			//in functie de valoarea acestuia.

			std::map<int, std::string>::const_iterator err_string = error_types.find(*err_code);
			if(err_string != error_types.end()) {
				if(*err_code != 1 && *err_code != 2)
					(get_acc_token->second->remained_ops)--;
				std::cout << err_string->second;
			}
			else
				std::cout <<"INTERNAL SERVER ERROR\n";
		}
		
	}

	return 0;
}
