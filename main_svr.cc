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
	std::string id = std::string(*pck);
	std::cout << "BEGIN " << id << " AUTHZ\n";
	general_message* data = (general_message*)calloc(1, sizeof(general_message));
	std::map<std::string, User_data_srv*>::iterator it = ID_REQ_TOKEN.find(id);
	if (it != ID_REQ_TOKEN.end()){
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
		
		char *token = generate_access_token(*pck);
		std::cout << "  RequestToken = " << token << "\n";
		data->type = 0;
		data->resp = token;
		auth_token_id_map.emplace(std::string(token), id);
		it->second->general_token = token;
	}else{
		data->type = 1;
		//Holy dang. RPC stubs do not accept NULL pointers. Put a string terminator
		//to avoid leaks.
		data->resp = (char*)calloc(1, sizeof(char));;
	}
	return data;
}

general_message* request_acc_token_1_svc(char** pck, struct svc_req *cl){
	char* approved_token = strstr(*pck, ",");
	*approved_token = '\0';
	approved_token++;
	char* renewal_char = strstr(approved_token, ",");
	*renewal_char = '\0';
	renewal_char++;

	std::map<std::string, User_data_srv*>::iterator it = ID_REQ_TOKEN.find(std::string(*pck));
	if (it != ID_REQ_TOKEN.end()) {
		general_message* response = (general_message*)calloc(1, sizeof(general_message));
		if(!strcmp(it->second->general_token, approved_token)) {
			response->type = 1;
			response->resp = (char *)calloc(1, sizeof(char));
		}
		else if ((it->second->remained_ops == 0) && it->second->refresh_token && !strcmp(it->second->refresh_token, approved_token)){
			std::cout << "BEGIN " << *pck << " AUTHZ REFRESH\n";
			char *auth_token = generate_access_token(it->second->refresh_token);
			char *refresh_token = generate_access_token(auth_token);
			std::cout << "  AccessToken = " << auth_token << "\n";
			std::cout << "  RefreshToken = " << refresh_token << "\n";
			free(it->second->general_token);
			free(it->second->refresh_token);
			it->second->general_token = auth_token;
			it->second->refresh_token = refresh_token;
			it->second->remained_ops = token_availability;
			acc_token_id_map.emplace(std::string(auth_token), it->first);
			response->resp = (char *)calloc(strlen(auth_token) + strlen(refresh_token) + std::to_string(token_availability).length() + 3, sizeof(char));
			memcpy(response->resp, auth_token, strlen(auth_token));
			strcat(response->resp, ",");
			strcat(response->resp, refresh_token); 
			strcat(response->resp, ",");
		
			response->type = 0;
			strcat(response->resp, std::to_string(token_availability).c_str());
			return response;
		}else {
			char *auth_token = generate_access_token(it->second->general_token);
			std::cout << "  AccessToken = " << auth_token << "\n";
			char* refresh_token = NULL;
			free(it->second->general_token);
			it->second->general_token = auth_token;
			it->second->remained_ops = token_availability;
			acc_token_id_map.emplace(std::string(auth_token), it->first);
			if(strcmp(renewal_char, "0") != 0){
				refresh_token = generate_access_token(auth_token);
				std::cout << "  RefreshToken = " << refresh_token << "\n";
				it->second->refresh_token = refresh_token;
			}
			response->resp = (char *)calloc(strlen(auth_token) + (it->second->refresh_token ? strlen(refresh_token) + 1: 0) + std::to_string(token_availability).length() + 2, sizeof(char));
			memcpy(response->resp, auth_token, strlen(auth_token));
			strcat(response->resp, ",");
			if(it->second->refresh_token){
				strcat(response->resp, refresh_token); 
				strcat(response->resp, ",");
			}
			response->type = 0;
			strcat(response->resp, std::to_string(token_availability).c_str());
		
			return response;
		}
	}
}
char** approve_request_token_1_svc(char** pck, struct svc_req *cl){
	auto top_perm = Perms.front();
	Perms.pop();
	char** return_token = (char**)calloc(1, sizeof(char *));
	return_token[0] = (char *)calloc(strlen(*pck) + 1, sizeof(char));
	memcpy(return_token[0], *pck, strlen(*pck));
	if (top_perm.compare("*,-")){
		std::map<std::string, std::string>::iterator it = auth_token_id_map.find(std::string(*pck));
		if(it == auth_token_id_map.end()){
			std::cout << "Avem o problema\n";
		}
		else{
			std::string getname = it->second;
			std::map<std::string, User_data_srv*>::iterator user_info = ID_REQ_TOKEN.find(getname);
			if (user_info != ID_REQ_TOKEN.end()){
				user_info->second->perms = strdup(top_perm.c_str());
				return_token[0][0] = (return_token[0][0] - 'A' + 5) % 58 + 'A';
			}
			auth_token_id_map.erase(it);
		}
	}
	return return_token;  
}
int* validate_delegated_action_1_svc(char** pck, struct svc_req *cl){
	static const std::map<std::string, char> available_ops = {	
													{"READ", 'R'},
													{"INSERT", 'I'},
													{"MODIFY", 'M'},
													{"DELETE", 'D'},
													{"EXECUTE", 'X'}
													};
	int* err = (int*)calloc(1, sizeof(int));
	*err = 4;
	char* accessed_res = strstr(*pck, ",");
	*accessed_res = '\0';
	accessed_res++;
	char* token = strstr(accessed_res, ",");
	*token = '\0';
	token++;
	if(token[0] == '\0'){
		*err = 1;
		std::cout << "DENY (" << *pck << "," << accessed_res << ",,0)\n";
		return err;
	}

	std::map<std::string, std::string>::iterator get_id = acc_token_id_map.find(std::string(token));
	if(get_id == acc_token_id_map.end()){
		*err = 1;
		std::cout << "DENY (" << *pck << "," << accessed_res << ",,0)\n";
		return err;
	}
	std::map<std::string, User_data_srv*>::iterator get_user = ID_REQ_TOKEN.find(get_id->second);
	if(get_user == ID_REQ_TOKEN.end()){
		std::cout << "Strange error. Will have to investigate.\n";
		*err = -1;
		return err;
	}

	if(get_user->second->remained_ops == 0){
		*err = 2;
		std::cout << "DENY (" << *pck << "," << accessed_res << ",,0)\n";
		return err;
	}
	if (AvailableRes.find(std::string(accessed_res)) == AvailableRes.end()){
		*err = 3;
		(get_user->second->remained_ops)--;
		std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
		return err;
	}
	char* find_res_in_perms = strstr(get_user->second->perms, accessed_res);
	if(!find_res_in_perms){
		*err = 4;
		(get_user->second->remained_ops)--;
		std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
		return err;
	}
	std::map<std::string, char>::const_iterator operation_translated = available_ops.find(std::string(*pck));
	if(operation_translated == available_ops.end()){
		*err = 4;
		(get_user->second->remained_ops)--;
		std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
		return err;
	}
	char* perms_for_res = find_res_in_perms + strlen(accessed_res) + 1;
	while(*perms_for_res != '\0' && *perms_for_res != ','){
		if(*perms_for_res == operation_translated->second){
			(get_user->second->remained_ops)--;
			std::cout << "PERMIT (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
			*err = 0;
			return err;
		}
		perms_for_res++;
	}
	(get_user->second->remained_ops)--;
	std::cout << "DENY (" << *pck << "," << accessed_res << "," << token << "," << get_user->second->remained_ops << ")\n";
	return err;
}


int main (int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	if (argc < 5) {
		std::cout << "Not enough arguments.\n";
		return -1;
	}

	{
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
