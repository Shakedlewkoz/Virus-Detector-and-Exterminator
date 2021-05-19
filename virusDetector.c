#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE * file;

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

typedef struct link link;
 
struct link {
    link *nextVirus;
    virus *vir;
};

struct fun_desc {
  char *name;
  void (*fun)(link*, FILE*);
};

int PrintHex(unsigned char *buffer, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02X ", buffer[i]);
    }
    return 0;
}

virus* readVirus(FILE * file, int indnum) {
    short s;
    fread(&s, 1, 2, file);
    if (indnum == 1) {
        s = (s << 8 | s >> 8);
    }
    virus *vir = malloc(sizeof(virus));
    vir->SigSize = s;
    char name[16];
    fread(name, 1, 16, file);
    for (int i = 0; i < 16; i++) {
        vir->virusName[i] = name[i];
    }
    unsigned char *sig = malloc(s);
    fread(sig, 1, s, file);
    vir->sig = sig;
    return vir;
}

void printVirus(virus* vir, FILE* input) {
    fprintf(stdout, "%s", "virus name: ");
    for (int i = 0; i < 16; i++) {
        fprintf(stdout, "%c", vir->virusName[i]);
    }
    fprintf(stdout, "\n%s", "Virus size: ");
    fprintf(stdout, "%d\n", vir->SigSize);
    fprintf(stdout, "%s", "signature: \n");    
    PrintHex(vir->sig, vir->SigSize);
    fprintf(stdout, "\n");
}


link* list_append(link* virus_list, virus* data) {
    if (virus_list->vir == NULL) {
        virus_list->nextVirus = NULL;
        virus_list->vir = data;
        return virus_list;
    }
    link *temp = virus_list;
    while (temp->nextVirus != NULL) {
        temp = temp->nextVirus;
    }
    link *l = malloc(sizeof(link));
    l->vir = data;
    l->nextVirus = NULL;
    temp->nextVirus = l;
    return virus_list;
}
 
void list_free(link *virus_list) {
    link *temp = virus_list;
    link *temp2 = virus_list;
    while (temp != NULL) {
        temp = temp->nextVirus;
        free(temp2->vir->sig);
        free(temp2->vir);
        temp2->nextVirus = NULL;
        free(temp2);
        temp2 = temp;
    }
} 

void loadSignatures(link *virus_list, FILE* input) {
    printf("enter file name: ");
    char namefile[100];
    fgets(namefile, 100, stdin);
    sscanf(namefile, "%s", namefile);
    FILE * f;
    f = fopen(namefile, "r+");
    fseek(f, 0, SEEK_END);
    int length = ftell(f);
    fseek(f, 3, SEEK_SET);
    char indtype = fgetc(f);
    int indnum = 0;
    if (indtype == 'B') { indnum = 1; }
    while (ftell(f) < length) {
        virus *vir;
        vir = readVirus(f, indnum);
        list_append(virus_list, vir);
    }
    memset(namefile, 0, 100);
    fclose(f);
}

void list_print(link *virus_list, FILE* output) {
     if (virus_list != NULL) {
          link *temp = virus_list;
          while (temp->nextVirus != NULL) {
               printVirus(temp->vir, stdout);
               fprintf(stdout, "%s", "\n");
               temp = temp->nextVirus;
          }
          printVirus(temp->vir, stdout);
     }
     fprintf(stdout, "%s", "\n");
}

void detect_virus(char *buffer, unsigned int size, link *virus_list, FILE* output) {
     link *temp = virus_list;
     int i = 0;
     while (temp->nextVirus != NULL) {
          i = 0;
          temp = temp->nextVirus;
          while (i < size) {
               if (memcmp(temp->vir->sig, buffer + i, temp->vir->SigSize) == 0) {
                    fprintf(output, "\nvirus start: %i\n", i);
                    fprintf(output, "virus name: %s\n", temp->vir->virusName);
                    fprintf(output, "virus sig length: %i\n\n", temp->vir->SigSize);
                    i = i + temp->vir->SigSize - 1;
               } 
               i++;
          }
     }
}

void detectViruses(link *virus_list, FILE* input) {
     printf("enter file name: ");
     char buffer[10000];
     char namefile[100];
     fgets(namefile, 100, stdin);
     sscanf(namefile, "%s", namefile);
     FILE * f;
     f = fopen(namefile, "r+");
     fseek(f, 0, SEEK_END);
     int length = ftell(f);
     fseek(f, 0, SEEK_SET);
     fread(buffer, 1, length, f);
     detect_virus(buffer, length, virus_list, stdout);
     memset(namefile, 0, 100);
     memset(buffer, 0, 10000);
     fclose(f);
}

void kill_virus(char *fileName, int signitureOffset, int signitureSize) {
    sscanf(fileName, "%s", fileName);
    FILE * f;
    f = fopen(fileName, "w+");
    fseek(f, signitureOffset, SEEK_SET);
    for (int j = 0; j < signitureSize; j++) {
        char *c = "0x90";
        fwrite(c, 1, 1, f);
        fseek(f, ftell(f) + 1, SEEK_SET);
    }
    fclose(f);
}

void fixFile(link *virus_list, FILE* input) {
    printf("enter file name: ");
    char namefile[100];
    fgets(namefile, 100, stdin);
    printf("enter the starting byte location: ");
    char inputa[50]; 
    int a = atoi(fgets(inputa, 50, stdin));
    printf("enter the size of the virus signature: ");
    char inputb[50]; 
    int b = atoi(fgets(inputb, 50, stdin));
    kill_virus(namefile, a, b);
}


int main (int argc, char** argv) {
    FILE * file = NULL;
    link *list = malloc(sizeof(link));
    struct fun_desc menu[] = {
         {"Load signatures", &loadSignatures}, {"Print signatures", &list_print}, {"Detect viruses", &detectViruses}, {"Fix file", &fixFile}, {NULL, NULL} };
    void (*f)(link*, FILE*);
    while (1) {
        int length = sizeof(menu)/sizeof(menu[0]) - 1;
        for (int i = 0; i < length; i++) {
            printf("%d) %s\n", i+1, menu[i].name);
        }
        fprintf(stdout, "Option: ");
        char input[50]; 
        int a = atoi(fgets(input, 50, stdin));
        a = a - 1;
        if (a >=0 && a < length) {
            printf("Within bounds\n");
        }
        else { 
            printf("Not within bounds\n"); 
            list_free(list);
            exit(1); 
        }
        f = menu[a].fun;
        f(list, file);
    }
    list_free(list);
    return 0;
}
