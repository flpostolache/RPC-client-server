#include "schema.h"
#include "essentials.h"
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <string>
#include <queue>
#include <iostream>
#include <fstream>
#include <string_view>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>

std::map<std::string, User_data_srv*> ID_REQ_TOKEN;
std::map<std::string, std::string> auth_token_id_map;
std::map<std::string, std::string> acc_token_id_map;
std::set<std::string> AvailableRes;
std::queue<std::string> Perms;
int token_availability = -1;

general_message* request_auth_1_svc(char** pck, struct svc_req *cl){
	// pck contine id-ul utilizatorului care doreste sa obtina token de acces
	std::string id = std::string(*pck);
	std::cout << "BEGIN " << id << " AUTHZ\n";

	// Alocare mesaj raspuns
	general_message* data = (general_message*)calloc(1, sizeof(general_message));
	// Cautam sa vedem daca ID-ul este prezent in baza de date de id-uri cunos-
	//cute.
	std::map<std::string, User_data_srv*>::iterator it = ID_REQ_TOKEN.find(id);
	if (it != ID_REQ_TOKEN.end()){
		// Verificam daca acest ID a mai facut un request de access in trecut.
		//Daca da, resetam toate aceste valori.
		if(it->second->general_token){
			std::map<std::string, std::string>::iterator get_id = acc_token_id_map.find(it->second->general_token);
			if(get_id != acc_token_id_map.end())
				acc_token_id_map.erase(get_id);
			free(it->second->general_token);
		}
		it->second->remained_ops = -1;
		if(it->second->perms)
			free(it->second->perms);
		if(it->second->refresh_token)
			free(it->second->refresh_token);
		
		// Generam token-ul de acces.
		char *token = generate_access_token(*pck);
		std::cout << "  RequestToken = " << token << "\n";

		// Marcam raspunsul ca fiind un mesaj cu continut.
		data->type = 0;
		// Intoarcem token-ul catre client.
		data->resp = token;
		// Ca sa nu fac o parcurgere a map-ului de clienti cand trebuie sa 
		//semnez jetonul de request, salvez in alt map grupul "req_token":"ID" 
		auth_token_id_map.emplace(std::string(token), id);
		// In structura clientului asociez token-ul generat cu ID-ul.
		it->second->general_token = token;
	}else{
		// Marcam raspunsul ca fiind un mesaj de eroare.
		data->type = 1;
		//	Holy dang. RPC stubs do not accept NULL pointers. Put a string 
		//terminator to avoid seg faults.
		data->resp = (char*)calloc(1, sizeof(char));
	}
	// Intorc raspunsul.
	return data;
}

general_message* request_acc_token_1_svc(char** pck, struct svc_req *cl){
	//	pck contine ID-ul utilizatorului, jetonul pentru autorizare si daca
	//utilizatorul doreste autoreimprospatare a token-ului de acces(marcat
	//cu 0 sau 1 ca in cerinta) Toate aceste date sunt separate prin cate
	//o virgula.

	// Extragem tokenul de aprobare/tokenul de reimprospatare.
	char* approved_token = strstr(*pck, ",");
	*approved_token = '\0';
	approved_token++;
	// Extragem tipul operatiei. In cazul token-ului de refresh acest camp
	//nu este folosit.
	char* renewal_char = strstr(approved_token, ",");
	*renewal_char = '\0';
	renewal_char++;

	// Alocare mesaj de raspuns
	general_message* response = (general_message*)calloc(1, sizeof(general_message));

	// Cautam daca ID-ul este in baza de date de id-uri cunoscute
	std::map<std::string, User_data_srv*>::iterator it = ID_REQ_TOKEN.find(std::string(*pck));
	if (it != ID_REQ_TOKEN.end()) {
		// Daca token-ul de aprobare este neschimbat, inseamna ca
		//cererea nu a fost aprobata. Intoarcem eroare.
		if(!strcmp(it->second->general_token, approved_token)) {
			response->type = 1;
			response->resp = (char *)calloc(1, sizeof(char));
		}
		// Vedem daca ID-ul curent nu mai poate face operatii si daca are
		//refresh token. Daca are si este egal cu cel primit in pachet,
		//generam o noua pereche de token-uri refresh-acces.
		else if ((it->second->remained_ops == 0) && it->second->refresh_token && !strcmp(it->second->refresh_token, approved_token)) {
			std::cout << "BEGIN " << *pck << " AUTHZ REFRESH\n";
			// Generare pereche token acces-refresh
			char *auth_token = generate_access_token(it->second->refresh_token);
			char *refresh_token = generate_access_token(auth_token);
			std::cout << "  AccessToken = " << auth_token << "\n";
			std::cout << "  RefreshToken = " << refresh_token << "\n";
			// Eliberam vechile token-uri.
			free(it->second->general_token);
			free(it->second->refresh_token);
			// Atribuim noile chei ID-ului si resetam numarul de operatii
			//valabile.
			it->second->general_token = auth_token; 
			it->second->refresh_token = refresh_token;
			it->second->remained_ops = token_availability;

			// Adaug in acest map perechea acc_token-id pentru a-mi fi
			//mai usor sa caut access-token-ul in "Validate Delegated 
			//Action".
			acc_token_id_map.emplace(std::string(auth_token), it->first);
			// Alocam spatiu pentru a trimite inapoi datele necesare catre client.
			response->resp = (char *)calloc(strlen(auth_token) + strlen(refresh_token) + std::to_string(token_availability).length() + 3, sizeof(char));
			memcpy(response->resp, auth_token, strlen(auth_token));
			strcat(response->resp, ",");
			strcat(response->resp, refresh_token); 
			strcat(response->resp, ",");

			// Marcam ca raspunsul nu este eroare si ca se vor trimite date.
			response->type = 0;
			strcat(response->resp, std::to_string(token_availability).c_str());
			return response;
		} else {

			approved_token[0] = ~(approved_token[0]);

			if (!strcmp(approved_token, it->second->general_token)){
				// Cazul ramas neacoperit de cerinta este cazul de generare
				//a unui token de acces cand se primeste un token de autori
				//zare, aprobat de utilizator.

				// Generam access token-ul.
				char *auth_token = generate_access_token(it->second->general_token);
				std::cout << "  AccessToken = " << auth_token << "\n";
				char* refresh_token = NULL;

				// Nu am vrut sa folosesc doua campuri separate pentru 
				//request token si auth token. Dupa ce ajung in acest punct,
				//request token-ul este inutil. Inlocuieste-l cu access token.
				free(it->second->general_token);
				it->second->general_token = auth_token;
				it->second->remained_ops = token_availability;
			
				// Adaug in acest map perechea acc_token-id pentru a-mi fi
				//mai usor sa caut access-token-ul in "Validate Delegated 
				//Action".
				acc_token_id_map.emplace(std::string(auth_token), it->first);

				// Verificam daca trebuie sa ii generezi si refresh token.
				if(strcmp(renewal_char, "0") != 0){
					refresh_token = generate_access_token(auth_token);
					std::cout << "  RefreshToken = " << refresh_token << "\n";
					it->second->refresh_token = refresh_token;
				}

				// Alocam spatiu in raspuns.
				response->resp = (char *)calloc(strlen(auth_token) + (it->second->refresh_token ? strlen(refresh_token) + 1: 0) + std::to_string(token_availability).length() + 2, sizeof(char));
				memcpy(response->resp, auth_token, strlen(auth_token));
				strcat(response->resp, ",");
				if(it->second->refresh_token){
					strcat(response->resp, refresh_token); 
					strcat(response->resp, ",");
				}

				// Marcam ca raspunsul nu este eroare si ca se vor trimite date.
				response->type = 0;
				strcat(response->resp, std::to_string(token_availability).c_str());
				return response;
			} else {
				// Marcam raspunsul ca fiind un mesaj de eroare.
				response->type = -1;
				//	Holy dang. RPC stubs do not accept NULL pointers. Put a string 
				//terminator to avoid seg faults.
				response->resp = (char*)calloc(1, sizeof(char));
			}
		}
		
	}
	else{
		// Marcam raspunsul ca fiind un mesaj de eroare.
		response->type = -1;
		//	Holy dang. RPC stubs do not accept NULL pointers. Put a string 
		//terminator to avoid seg faults.
		response->resp = (char*)calloc(1, sizeof(char));
	}
}
char** approve_request_token_1_svc(char** pck, struct svc_req *cl){
	// pck contine token-ul pentru autorizarea cererii de acces

	// Extragem urmatorul set de permisiuni.
	auto top_perm = Perms.front();
	Perms.pop();

	// Alocam tokenul pe care o sa il primeasca inapoi clientul.
	// (validat sau nu)
	char** return_token = (char**)calloc(1, sizeof(char *));
	return_token[0] = (char *)calloc(strlen(*pck) + 1, sizeof(char));
	memcpy(return_token[0], *pck, strlen(*pck));

	// Daca permisiunile permit ceva
	if (top_perm.compare("*,-")){

		// Cautam ID-ul care are token-ul pentru autorizarea cererii de acces
		//egal cu cel primit ca parametru.
		std::map<std::string, std::string>::iterator it = auth_token_id_map.find(std::string(*pck));
		if(it == auth_token_id_map.end()){
			// Intoarcem token-ul nesemnat deoarece nu am gasit un id 
			//care sa aiba ca referinta acest token.
			return return_token;
		}
		else{
			// Ataseaza acelui ID, setul de permisiuni extras si marcheaza
			//tokenul ca fiind semnat.
			std::string getname = it->second;
			std::map<std::string, User_data_srv*>::iterator user_info = ID_REQ_TOKEN.find(getname);
			if (user_info != ID_REQ_TOKEN.end()){
				user_info->second->perms = strdup(top_perm.c_str());
				return_token[0][0] = ~(return_token[0][0]);
			}
			// Sterge intrarea din map deoarece nu mai este de ajutor.
			auth_token_id_map.erase(it);
		}
	}
	return return_token;  
}
int* validate_delegated_action_1_svc(char** pck, struct svc_req *cl){
	//	pck contine tipul operatiei, resursa accesata si jetonul de acces,
	//toate separate prin cate o virgula

	// Map static cu toate operatiile posibile si corespondentul sau 
	//din approvals.db. Daca o sa mai apara operatii noi, trebuie adaugate
	//aici.
	static const std::map<std::string, char> available_ops = {	
													{"READ", 'R'},
													{"INSERT", 'I'},
													{"MODIFY", 'M'},
													{"DELETE", 'D'},
													{"EXECUTE", 'X'}
													};

	// Intoarcem doar un cod de eroare
	// Codificare err:
	// 0 -> PERMISSION_GRANTED
	// 1 -> PERMISSION_DENIED
	// 2 -> TOKEN_EXPIRED
	// 3 -> RESOURCE_NOT_FOUND
	// 4 -> OPERATION_NOT_PERMITTED
	int* err = (int*)calloc(1, sizeof(int));
	// Initializez err cu "Operation_not_permittted" ca sa pot utiliza
	// eficient logica de mai jos.
	*err = 4;

	// Extragem resursa pe care dorim sa o accesam
	char* accessed_res = strstr(*pck, ",");
	*accessed_res = '\0';
	accessed_res++;

	// Extragem tokenul de acces
	char* token = strstr(accessed_res, ",");
	*token = '\0';
	token++;

	// Daca tokenul este gol (cineva face request fara token)
	if(token[0] == '\0'){
		*err = 1;
		std::cout << "DENY (" << *pck << "," << accessed_res << ",,0)\n";
		return err;
	}

	//	Daca tokenul nu este gol, dar nu este un token de acces valid.
	std::map<std::string, std::string>::iterator get_id = acc_token_id_map.find(std::string(token));
	if(get_id == acc_token_id_map.end()){
		*err = 1;
		std::cout << "DENY (" << *pck << "," << accessed_res << ",,0)\n";
		return err;
	}
	//	Daca tokenul nu este gol, este valid, dar id-ul corespunzator nu este in
	//baza de date cu ID-uri disponibile. Hope it will never happen, but I will
	//keep it here.
	std::map<std::string, User_data_srv*>::iterator get_user = ID_REQ_TOKEN.find(get_id->second);
	if(get_user == ID_REQ_TOKEN.end()){
		std::cout << "Strange error. Will have to investigate.\n";
		*err = -1;
		return err;
	}

	// Daca utilizatorul nu mai poate face operatii
	if(get_user->second->remained_ops == 0){
		*err = 2;
		std::cout << "DENY (" << *pck << "," << accessed_res << ",,0)\n";
		return err;
	}

	// Daca nu gasim resursa pe care acesta vrea sa o prelucreze
	if (AvailableRes.find(std::string(accessed_res)) == AvailableRes.end()){
		*err = 3;
		(get_user->second->remained_ops)--;
		std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
		return err;
	}

	// Vedem daca access token-ul are acces la acea resursa
	char* find_res_in_perms = strstr(get_user->second->perms, accessed_res);
	if(!find_res_in_perms){
		*err = 4;
		(get_user->second->remained_ops)--;
		std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
		return err;
	}

	// Vedem daca operatia pe care acesta doreste sa o realizeze este cunos-
	//cuta de server.
	std::map<std::string, char>::const_iterator operation_translated = available_ops.find(std::string(*pck));
	if(operation_translated == available_ops.end()){
		*err = 4;
		(get_user->second->remained_ops)--;
		std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
		return err;
	}

	// Vedem daca acces token-ul poate face operatia dorita pe resursa
	//selectata.
	char* perms_for_res = find_res_in_perms + strlen(accessed_res) + 1;
	while(*perms_for_res != '\0' && *perms_for_res != ','){
		if(*perms_for_res == operation_translated->second){
			(get_user->second->remained_ops)--;
			// Victorie! 
			std::cout << "PERMIT (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
			*err = 0;
			return err;
		}
		perms_for_res++;
	}
	// Am parcurs toata lista de operatii permise pentru resursa specificata. 
	//Nu am gasit operatia dorita. Intoarcem deny.
	(get_user->second->remained_ops)--;
	std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
	return err;
}


int main (int argc, char **argv)
{
	// Opresc buffering-ul pe stdout
	setvbuf(stdout, NULL, _IONBF, 0);

	// Verific sa am suficiente argumente
	if (argc < 5) {
		std::cout << "Not enough arguments.\n";
		return -1;
	}

	{
		// Citim toti utilizatorii cunoscuti si ii adaugam in baza de date
		//cu utilizatori cunoscuti.
		std::string ID_string;
		std::ifstream UserId_file(argv[1]);
		getline(UserId_file, ID_string);
		int ID;
		sscanf(ID_string.c_str(), "%d", &ID);
		for(int i = 0; i < ID; i++) {
			getline(UserId_file, ID_string);
			User_data_srv* aux = (User_data_srv*)calloc(1, sizeof(User_data_srv));
			ID_REQ_TOKEN.emplace(ID_string, aux);
		}
		UserId_file.close();
	}

	{
		// Citim toate resursele disponibile
		std::string ID_string;
		std::ifstream UserId_file(argv[2]);
		getline(UserId_file, ID_string);
		int ID;
		sscanf(ID_string.c_str(), "%d", &ID);
		for(int i = 0; i < ID; i++) {
			getline(UserId_file, ID_string);
			AvailableRes.emplace(ID_string);
		}
		UserId_file.close();
	}

	{
		// Citim toate permisiunile disponibile
		std::string ID_string;
		std::ifstream UserId_file(argv[3]);
		while(getline(UserId_file, ID_string)){
			Perms.push(ID_string);
		}
		UserId_file.close();
	}

	sscanf(argv[4], "%d", &token_availability);

	register SVCXPRT *transp;

	pmap_unset (PROGRAM, VERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, PROGRAM, VERS, program_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (PROGRAM, VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, PROGRAM, VERS, program_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (PROGRAM, VERS, tcp).");
		exit(1);
	}

	svc_run();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}
