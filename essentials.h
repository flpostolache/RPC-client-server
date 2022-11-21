#include "schema.h"
#include "token.h"


void program_1(struct svc_req *rqstp, register SVCXPRT *transp);


struct __User_data_srv{
    int remained_ops;
    char* general_token;
    char* perms;
    char* refresh_token;
}; 

typedef struct __User_data_srv User_data_srv;

struct __User_data_clt{
    int remained_ops;
    char* general_token;
    char* refresh_token;
}; 

typedef struct __User_data_clt User_data_clt;

/*struct __general_message
{
    int type;
    void* data;
};

typedef struct __general_message general_message;*/

/*typedef struct __client_data_srv
{
    bool auto_renew;
    char ID[16];
    char *perm;
    char 
}client_data_srv;*/
