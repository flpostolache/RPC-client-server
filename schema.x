/* 
    Structura generica pe care o folosesc de obicei cand nu prea stiu de ce
variabile o sa am nevoie. Campul type specifica daca mesajul este de tip 
eroare sau s-au trimis date. Voi detalia pe cod ce se trimite prin el
in fiecare caz.
*/
struct __general_message
{
    int type;
    string resp<>;
};

typedef struct __general_message general_message;

program PROGRAM {
    version VERS {
        general_message REQUEST_AUTH(string pck) = 1;
        general_message REQUEST_ACC_TOKEN(string pck) = 2;
        string APPROVE_REQUEST_TOKEN(string pck) = 3;
        int VALIDATE_DELEGATED_ACTION(string pck) = 4;
    } = 1;
} = 0x31234568;