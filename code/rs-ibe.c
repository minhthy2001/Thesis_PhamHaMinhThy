#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "../pbc-0.5.14/misc/symtab.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

/*
============================================================================
                                GLOBAL VARIABLES
============================================================================
*/

#define DEPTH 3
#define NUMBER_OF_NODES 8

#define AES_BLOCK_SIZE 16
#define BASE10 10

pairing_t pairing;

char *revokedList[NUMBER_OF_NODES];

struct public_pars_type
{
    element_t g;
    element_t g1;
    element_t g2;
    element_t alpha;
    element_t r0;
    element_t r1;
    element_t u[DEPTH + 1];
    element_t h[DEPTH + 1];
};

struct private_pars_type
{
    element_t Fu;
    element_t Fh;
    element_t sv;
    element_t st;
};

struct g_theta_type
{
    element_t g_theta_0;
    element_t g_theta_1;
};

struct r_theta_type
{
    element_t r_theta_0;
    element_t r_theta_1;
};

struct secret_key_type
{
    element_t SK0;
    element_t SK1;
};

struct key_update_type
{
    element_t KU0;
    element_t KU1;
};

struct decrypt_key_type
{
    element_t DK1;
    element_t DK2;
    element_t DK3;
};

struct cipher_V
{
    element_t Cv0;
    element_t Cv1;
    element_t Cv2;
};

struct cipher_type
{
    element_t C0;
    element_t C1;
    element_t C2;
    struct cipher_V Cv;
};

struct node
{
    char *value;
    struct node *next;
};

symtab_t gDict;
symtab_t rDict;
symtab_t skDict;
symtab_t kuDict;
char **To;
char **To_prime;
element_t *Cv_values;

/*
============================================================================
                            FINDING ELEMENTS IN TO
============================================================================
*/

void binStr2Digit(int *digit, char *binStr)
{
    for (int i = 0; binStr[i] != '\0'; i++)
    {
        digit[i] = binStr[i] - 48;
    }
}

void num2binStr(char *binStr, int num, int length)
{
    /* Convert a decimal number into a binary string */
    for (int i = 1; i <= length; i++)
    {
        int n = num >> (i - 1); // get the last bit
        if (n & 1)
            binStr[length - i] = 49; // 1 = 49 (ASCII)
        else
            binStr[length - i] = 48; // 0 = 48 (ASCII)
        n = n >> 1;
    }
    binStr[length] = 0;
}

int num_of_to_element(int node_id)
{
    /* Compute number of elements in T for a specific node_id */
    int ones = 0;
    for (int i = 0; i < DEPTH; i++)
    {
        ones += node_id >> i & 1;
    }
    char node_id_str[DEPTH];
    num2binStr(node_id_str, node_id, DEPTH);
    return DEPTH - ones + 1;
}

char **findTo(int node_id)
{
    /* CTNodes
        Inputs: node_id and T's depth
        Output: a pointer to array of strings
    */
    int num_of_str = num_of_to_element(node_id);

    // declare to_dynamic to hold IDs of T's elements
    // it is an array of strings (IDs are strings)
    char **to_dynamic;
    to_dynamic = malloc(num_of_str * sizeof(char *));
    int to_index = 0; // index for to_dynamic

    int temp = node_id;
    char str[DEPTH];
    num2binStr(str, temp, DEPTH);

    // add the leaf node as the first element in T
    to_dynamic[to_index] = malloc(sizeof(str));
    strcpy(to_dynamic[to_index], str);
    to_index++;

    // compute other elements in T
    // and put them in to_dynamic as strings
    for (int i = 0; i < DEPTH; i++)
    {
        int num = temp;
        if ((num & 1) == 0)
        {
            num2binStr(str, temp + 1, DEPTH - i);
            to_dynamic[to_index] = malloc(sizeof(str));
            strcpy(to_dynamic[to_index], str);
            to_index++;
        }
        temp = temp >> 1;
    }

    // print/access IDs in T
    printf("To\n");
    for (int i = 0; i < num_of_str; i++)
    {
        printf("main: element %d  = %s\n", i, to_dynamic[i]);
    }

    return to_dynamic;
}

char **findPath(int user_id)
{
    /* findPath
        Inputs: user_id and T's depth
        Output: a pointer to array of strings
    */

    // declare path_dynamic to hold IDs of T's elements
    // it is an array of strings (IDs are strings)
    char **path_dynamic;
    path_dynamic = malloc(DEPTH * sizeof(char *));
    int to_index = 0; // index for path_dynamic

    int temp = user_id;
    char str[DEPTH];
    num2binStr(str, temp, DEPTH);

    // add the leaf node as the first element in path
    path_dynamic[to_index] = malloc(sizeof(str));
    strcpy(path_dynamic[to_index], str);
    printf("path[%d] = %s\n", to_index, path_dynamic[to_index]);
    to_index++;

    // compute other elements in path
    // and put them in path_dynamic as strings
    for (int i = 1; i < DEPTH; i++)
    {
        // shift left 1 bit
        temp = temp >> 1;
        // convert dec to binary string
        num2binStr(str, temp, DEPTH - i);
        // save binary string to path_dynamic array
        path_dynamic[to_index] = malloc(sizeof(str));
        strcpy(path_dynamic[to_index], str);
        to_index++;
    }

    return path_dynamic;
}

/*
findKUNodes
1. Mark the ancestors of revoked nodes as revoked -> X
2. Output non-revoked children of revoked nodes -> Y
*/
struct node *findKUNodes(struct node *headY, char *time, char **RL)
{
    struct node headX = {"X", NULL};
    headY->value = "Y";
    headY->next = NULL;
    struct node *currentX = &headX;
    struct node *currentY = headY;
    int revokedNode;

    // Create linked list X
    int i = 0;
    while (RL[i] != NULL)
    {
        // if ti <= t --> revoke
        revokedNode = (int)strtol(RL[i], NULL, 2);
        printf("revokedNode = %d\n", revokedNode);
        // find Path to nodes in RL
        char **Path = findPath(revokedNode);
        // add Path to X
        for (int j = 0; j < DEPTH; j++)
        {
            struct node *newNode = malloc(sizeof(struct node));
            newNode->value = Path[j];
            newNode->next = NULL;
            currentX->next = newNode;
            currentX = newNode;
        }
        if (*RL[i] == '\0')
        {
            printf("break\n");
            break;
        }
        i++;
    }

    currentX = &headX;
    struct node *theta_child;

    // Loop thru X to find theta_left and theta_right
    while (currentX != NULL)
    {
        // leaf nodes don't have children
        if (strlen(currentX->value) == 3)
        {
            currentX = currentX->next;
            continue;
        }

        // find theta_left and theta_right for each node in X
        char theta_left[DEPTH + 1];
        char theta_right[DEPTH + 1];
        int i = 0;

        if (strcmp(currentX->value, "X") == 0)
        {
            theta_left[0] = '0';
            theta_right[0] = '1';
            theta_left[1] = '\0';
            theta_right[1] = '\0';
        }
        else
        {
            char temp = currentX->value[i];
            while (temp != '\0')
            {
                theta_left[i] = temp;
                theta_right[i] = temp;
                temp = currentX->value[++i];
            }
            theta_left[i] = '0';
            theta_right[i] = '1';
            theta_left[i + 1] = '\0';
            theta_right[i + 1] = '\0';
        }

        theta_child = &headX;

        int leftInX = 0;
        int rightInX = 0;

        /*
        Create another pointer
        Loop thru X
        Compare theta_left and theta_right to each node in X
        */
        while (theta_child != NULL)
        {
            // if theta_left == a node in X --> set leftInX to true
            if (strcmp(theta_left, theta_child->value) == 0)
            {
                leftInX = 1;
            }
            // if theta_right == a node in X --> set rightInX to true
            if (strcmp(theta_right, theta_child->value) == 0)
            {
                rightInX = 1;
            }

            theta_child = theta_child->next;
        }

        // if leftInX is false --> add node to Y
        if (leftInX == 0)
        {
            struct node *newNodeY = malloc(sizeof(struct node));
            char *newYvalue = malloc(sizeof(theta_left));
            strcpy(newYvalue, theta_left);
            newNodeY->value = newYvalue;
            newNodeY->next = NULL;
            currentY->next = newNodeY;
            currentY = newNodeY;
        }

        // if rightInX is false --> add node to Y
        if (rightInX == 0)
        {
            struct node *newNodeY = malloc(sizeof(struct node));
            char *newYvalue = malloc(sizeof(theta_right));
            strcpy(newYvalue, theta_right);
            newNodeY->value = newYvalue;
            newNodeY->next = NULL;
            currentY->next = newNodeY;
            currentY = newNodeY;
        }

        currentX = currentX->next;
    }

    currentY = headY;
    printf("Y = ");
    while (currentY != NULL)
    {
        printf("%s\t", currentY->value);
        currentY = currentY->next;
    }
    printf("\n");
    return headY;
}

int isPrefix(char *str1, char *str2)
{
    while (*str1 != '\0' && *str1 == *str2)
    {
        str1++;
        str2++;
    }

    return *str1 == '\0' ? 1 : 0;
}

int getNumEleCv(char **to, int num_of_str)
{
    int size = 0;
    for (int i = 0; i < num_of_str; i++)
    {
        size += DEPTH - strlen(to[i]) + 1;
    }
    printf("getNumEleC: number of elements in To is: %d\n", size);
    return size;
}

int getOffsetCv(char **to, char *id, int num_of_str)
{
    int offset = 0;
    for (int i = 0; i < num_of_str; i++)
    {
        if (strcmp(to[i], id) != 0)
        {
            offset += DEPTH - strlen(to[i]) + 1;
        }
        else
        {
            break;
        }
    }
    printf("getOffsetCv: index of %s in To is: %d\n", id, offset);
    return offset;
}

/*
============================================================================
                            RS-IBE FUNCTIONS
============================================================================
*/

void Setup(struct public_pars_type *pp)
{

    element_init_G1(pp->g, pairing);
    element_init_G1(pp->g1, pairing);
    element_init_Zr(pp->alpha, pairing);
    element_init_G1(pp->g2, pairing);
    element_init_Zr(pp->r0, pairing);
    element_init_Zr(pp->r1, pairing);

    element_random(pp->g);
    element_printf("g = %B\n", pp->g);

    element_random(pp->g2);
    element_printf("g2 = %B\n", pp->g2);

    element_random(pp->alpha);
    element_printf("alpha = %B\n", pp->alpha);

    // g1 = g^alpha
    element_pow_zn(pp->g1, pp->g, pp->alpha);
    element_printf("g1 = %B\n", pp->g1);

    element_random(pp->r0);
    element_printf("r0 = %B\n", pp->r0);
    element_random(pp->r1);
    element_printf("r1 = %B\n", pp->r1);

    for (int i = 0; i < 4; i++)
    {
        element_init_G1(pp->u[i], pairing);
        element_init_G1(pp->h[i], pairing);
        element_random(pp->u[i]);
        element_random(pp->h[i]);
    }
}

void FuncDef(char *user, char *t, struct public_pars_type *pp, struct private_pars_type *pr)
{
    element_t u_pow_id, h_pow_time;
    int id_digit[DEPTH], t_digit[DEPTH];
    element_t id[DEPTH], time[DEPTH];

    binStr2Digit(id_digit, user);
    binStr2Digit(t_digit, t);
    for (int i = 0; i < DEPTH; i++)
    {
        element_init_Zr(id[i], pairing);
        element_init_Zr(time[i], pairing);
    }

    // ID = digit | time = digit
    for (int i = 0; i < DEPTH; i++)
    {
        element_set_si(id[i], id_digit[i]);
        element_set_si(time[i], t_digit[i]);
    }

    element_init_G1(pr->Fu, pairing);
    element_init_G1(pr->Fh, pairing);

    element_init_G1(u_pow_id, pairing);
    element_init_G1(h_pow_time, pairing);

    element_set(pr->Fu, pp->u[0]);
    for (int i = 0; i < DEPTH; i++)
    {
        element_pow_zn(u_pow_id, pp->u[i + 1], id[i]);
        element_mul(pr->Fu, pr->Fu, u_pow_id);
    }
    element_printf("Fu = %B\n", pr->Fu);

    element_set(pr->Fh, pp->h[0]);
    for (int i = 0; i < DEPTH; i++)
    {
        element_pow_zn(h_pow_time, pp->h[i + 1], time[i]);
        element_mul(pr->Fh, pr->Fh, h_pow_time);
    }
    element_printf("Fh = %B\n", pr->Fh);
}

void SKGen(struct public_pars_type *pp, struct private_pars_type *pr, char **path_to_node)
{
    struct g_theta_type *g_value;
    struct r_theta_type *r_value;
    element_t Fu_pow_r_theta_0, g_theta_0_pow_alpha;

    element_init_G1(Fu_pow_r_theta_0, pairing);
    element_init_G1(g_theta_0_pow_alpha, pairing);

    for (int i = 0; i < DEPTH; i++)
    {
        struct g_theta_type *g = malloc(sizeof(struct g_theta_type));
        element_init_G1(g->g_theta_0, pairing);
        element_init_G1(g->g_theta_1, pairing);
        /*
        if g0 hasn't been defined, calculate g and put in gDict
        else, extract value of g0 to calculate SK
        */
        if (!symtab_has(gDict, path_to_node[i]))
        {
            element_random(g->g_theta_0);
            element_printf("g_theta_0 = %B\n", g->g_theta_0);
            // g_theta_1 = g2 / g_theta_0
            element_div(g->g_theta_1, pp->g2, g->g_theta_0);
            element_printf("g_theta_1 = %B\n", g->g_theta_1);

            /*
                Put g as the value of key ID in gDict
                key : ID
                value  : struct g
            */
            symtab_put(gDict, g, path_to_node[i]);
        }
        g_value = symtab_at(gDict, path_to_node[i]);
        element_printf("%s : g0 = %B\n", path_to_node[i], g_value->g_theta_0);
        element_printf("%s : g1 = %B\n", path_to_node[i], g_value->g_theta_1);

        struct r_theta_type *r = malloc(sizeof(struct r_theta_type));
        element_init_Zr(r->r_theta_0, pairing);
        element_init_Zr(r->r_theta_1, pairing);
        if (!symtab_has(rDict, path_to_node[i]))
        {
            element_random(r->r_theta_0);
            element_printf("r_theta_0 = %B\n", r->r_theta_0);
            element_random(r->r_theta_1);
            element_printf("r_theta_1 = %B\n", r->r_theta_1);
            /*
                Put r as the value of key ID in gDict
                key : ID
                value  : struct r
            */
            symtab_put(rDict, r, path_to_node[i]);
        }
        r_value = symtab_at(rDict, path_to_node[i]);
        element_printf("%s : r0 = %B\n", path_to_node[i], r_value->r_theta_0);
        element_printf("%s : r1 = %B\n", path_to_node[i], r_value->r_theta_1);

        element_pow_zn(g_theta_0_pow_alpha, g_value->g_theta_0, pp->alpha);
        element_pow_zn(Fu_pow_r_theta_0, pr->Fu, r_value->r_theta_0);

        struct secret_key_type *sk = malloc(sizeof(struct secret_key_type));
        element_init_G1(sk->SK0, pairing);
        element_init_G1(sk->SK1, pairing);
        element_mul(sk->SK0, g_theta_0_pow_alpha, Fu_pow_r_theta_0);
        element_printf("SK0 = %B\n", sk->SK0);
        element_pow_zn(sk->SK1, pp->g, r_value->r_theta_0);
        element_printf("SK1 = %B\n", sk->SK1);

        symtab_put(skDict, sk, path_to_node[i]);
    }
}

void KeyUpdate(struct public_pars_type *pp, struct private_pars_type *pr, char *time, struct node *KUNodes)
{
    struct g_theta_type *g1_value;
    struct r_theta_type *r_value;
    element_t g_theta_1_pow_alpha, Fh_pow_r_theta_1;

    element_init_G1(g_theta_1_pow_alpha, pairing);
    element_init_G1(Fh_pow_r_theta_1, pairing);

    struct node *current = KUNodes;
    while (current != NULL)
    {
        struct g_theta_type *g = malloc(sizeof(struct g_theta_type));
        element_init_G1(g->g_theta_0, pairing);
        element_init_G1(g->g_theta_1, pairing);
        /*
        if g1 hasn't been defined, calculate g and put in gDict
        else, extract value of g1 to calculate KU
        */
        if (!symtab_has(gDict, current->value))
        {
            printf("New node\n");
            element_random(g->g_theta_0);
            // g_theta_1 = g2 / g_theta_0
            element_div(g->g_theta_1, pp->g2, g->g_theta_0);

            /*
                Put g as the value of key ID in gDict
                key : value
                id  : struct g
            */
            symtab_put(gDict, g, current->value);
        }

        g1_value = symtab_at(gDict, current->value);
        element_printf("%s : g0 = %B\n", current->value, g1_value->g_theta_0);
        element_printf("%s : g1 = %B\n", current->value, g1_value->g_theta_1);

        struct r_theta_type *r = malloc(sizeof(struct r_theta_type));
        element_init_Zr(r->r_theta_0, pairing);
        element_init_Zr(r->r_theta_1, pairing);
        if (!symtab_has(rDict, current->value))
        {
            element_random(r->r_theta_1);
            element_printf("r_theta_1 = %B\n", r->r_theta_1);
            /*
                Put r as the value of key ID in gDict
                key : ID
                value  : struct r
            */
            symtab_put(rDict, r, current->value);
        }
        r_value = symtab_at(rDict, current->value);
        element_printf("%s : r0 = %B\n", current->value, r_value->r_theta_0);
        element_printf("%s : r1 = %B\n", current->value, r_value->r_theta_1);

        element_pow_zn(g_theta_1_pow_alpha, g1_value->g_theta_1, pp->alpha);
        element_pow_zn(Fh_pow_r_theta_1, pr->Fh, r_value->r_theta_1);

        struct key_update_type *ku = malloc(sizeof(struct key_update_type));
        element_init_G1(ku->KU0, pairing);
        element_init_G1(ku->KU1, pairing);
        element_mul(ku->KU0, g_theta_1_pow_alpha, Fh_pow_r_theta_1);
        element_printf("KU0 = %B\n", ku->KU0);
        element_pow_zn(ku->KU1, pp->g, r_value->r_theta_1);
        element_printf("g = %B\n", pp->g);
        element_printf("%s : r_theta_1 = %B\n", current->value, r_value->r_theta_1);
        element_printf("KU1 = %B\n", ku->KU1);

        symtab_put(kuDict, ku, current->value);
        current = current->next;
    }
}

void DKGen(struct public_pars_type *pp, struct private_pars_type *pr, struct decrypt_key_type *dk, char *user, char **path_to_node, struct node *KUNodes)
{
    element_printf("r0 = %B\n", pp->r0);
    element_printf("r1 = %B\n", pp->r1);

    element_t Fu_pow_r0, Fh_pow_r1;
    element_init_G1(Fu_pow_r0, pairing);
    element_init_G1(Fh_pow_r1, pairing);
    element_pow_zn(Fu_pow_r0, pr->Fu, pp->r0);
    element_printf("Fu = %B\n", pr->Fu);
    element_pow_zn(Fh_pow_r1, pr->Fh, pp->r1);
    element_printf("Fh = %B\n", pr->Fh);
    element_t FuFh, SKKU;
    element_init_G1(FuFh, pairing);
    element_init_G1(SKKU, pairing);
    element_mul(FuFh, Fu_pow_r0, Fh_pow_r1);

    struct secret_key_type *SK_theta;
    struct key_update_type *KU_theta;
    struct node *current = KUNodes;

    for (int i = 0; i < DEPTH; i++)
    {
        while (current != NULL)
        {
            if (strcmp(path_to_node[i], current->value) == 0)
            {
                SK_theta = symtab_at(skDict, path_to_node[i]);
                element_printf("%s : SK0 = %B\n", path_to_node[i], SK_theta->SK0);
                element_printf("%s : SK1 = %B\n", path_to_node[i], SK_theta->SK1);
                KU_theta = symtab_at(kuDict, current->value);
                element_printf("%s : KU0 = %B\n", current->value, KU_theta->KU0);
                element_printf("%s : KU1 = %B\n", current->value, KU_theta->KU1);
            }
            current = current->next;
        }
        current = KUNodes;
    }

    element_mul(SKKU, SK_theta->SK0, KU_theta->KU0);
    element_t g_pow_r0, g_pow_r1;
    element_init_G1(g_pow_r0, pairing);
    element_init_G1(g_pow_r1, pairing);
    element_pow_zn(g_pow_r0, pp->g, pp->r0);
    element_pow_zn(g_pow_r1, pp->g, pp->r1);

    element_init_G1(dk->DK1, pairing);
    element_init_G1(dk->DK2, pairing);
    element_init_G1(dk->DK3, pairing);
    element_mul(dk->DK1, SKKU, FuFh);
    element_mul(dk->DK2, SK_theta->SK1, g_pow_r0);
    element_mul(dk->DK3, KU_theta->KU1, g_pow_r1);
    element_printf("DK1 = %B\n", dk->DK1);
    element_printf("DK2 = %B\n", dk->DK2);
    element_printf("DK3 = %B\n", dk->DK3);
}

// Calculate all nodes v belongs to To
void Encrypt(struct public_pars_type *pp, struct private_pars_type *pr, struct cipher_type *ct, char *t, element_t key)
{
    int time_period_id = (int)strtol(t, NULL, 2);
    To = findTo(time_period_id);
    element_t *bv;
    element_printf("M before = %B\n", key);

    element_t h_pow_time;
    element_t g_pow_st;
    element_init_G1(h_pow_time, pairing);
    element_init_Zr(pr->st, pairing);
    element_random(pr->st);
    element_init_G1(g_pow_st, pairing);

    element_init_GT(ct->C0, pairing);
    element_init_G1(ct->C1, pairing);
    element_init_G1(ct->C2, pairing);
    element_init_G1(ct->Cv.Cv0, pairing);
    element_init_G1(ct->Cv.Cv1, pairing);
    element_init_G1(ct->Cv.Cv2, pairing);

    element_t e_g1g2_pow_st;
    element_init_GT(e_g1g2_pow_st, pairing);
    element_pairing(e_g1g2_pow_st, pp->g1, pp->g2);
    element_pow_zn(e_g1g2_pow_st, e_g1g2_pow_st, pr->st);

    // C0
    element_mul(ct->C0, key, e_g1g2_pow_st);
    element_printf("C0 = %B\n", ct->C0);
    // C1
    element_pow_zn(g_pow_st, pp->g, pr->st);
    element_printf("g_pow_st = %B\n", g_pow_st);
    element_invert(ct->C1, g_pow_st);
    element_printf("C1 = %B\n", ct->C1);
    // C2
    element_pow_zn(ct->C2, pr->Fu, pr->st);
    element_printf("C2 = %B\n", ct->C2);

    // Cv
    int bvlen;
    int idxCv = 0;
    int numCvElem;
    int count;
    // Cv_values: array with length defined by Cv_length
    int Cv_length = getNumEleCv(To, num_of_to_element(time_period_id));
    Cv_values = malloc(Cv_length * sizeof(element_t));
    element_t Fh_temp;
    element_init_G1(Fh_temp, pairing);
    for (int i = 0; i < num_of_to_element(time_period_id); i++)
    {
        printf("bv = %s\n", To[i]);
        bvlen = strlen(To[i]);
        bv = malloc(bvlen * sizeof(element_t));
        numCvElem = DEPTH - bvlen + 1;
        count = 0;
        for (int j = 0; j < bvlen; j++)
        {
            element_init_Zr(bv[j], pairing);
            element_set_si(bv[j], To[i][j] - 48);
        }
        // Cv0
        element_set(ct->Cv.Cv0, pp->h[0]);
        element_printf("Cv0 = %B\n", ct->Cv.Cv0);
        for (int k = 0; k < bvlen; k++)
        {
            element_pow_zn(h_pow_time, pp->h[k + 1], bv[k]);
            element_mul(ct->Cv.Cv0, ct->Cv.Cv0, h_pow_time);
        }
        element_pow_zn(ct->Cv.Cv0, ct->Cv.Cv0, pr->st);
        element_printf("Cv0 = %B\n", ct->Cv.Cv0);
        element_init_G1(Cv_values[idxCv], pairing);
        element_set(Cv_values[idxCv], ct->Cv.Cv0);
        element_printf("Cv_values[%d] = %B\n", idxCv, Cv_values[idxCv]);
        element_t temp1;
        element_init_G1(temp1, pairing);
        element_mul(temp1, pp->h[0], pp->h[1]);
        element_pow_zn(temp1, temp1, pr->st);
        element_printf("(h0h1)^st = %B\n", temp1);

        idxCv++;
        count++;
        if (count < numCvElem)
        {
            // Cv_|bv|+1
            element_pow_zn(ct->Cv.Cv1, pp->h[idxCv], pr->st);
            element_printf("Cv2 = %B\n", ct->Cv.Cv1);
            element_init_G1(Cv_values[idxCv], pairing);
            element_set(Cv_values[idxCv], ct->Cv.Cv1);
            element_printf("Cv_values[%d] = %B\n", idxCv, Cv_values[idxCv]);
            idxCv++;
            count++;
        }
        if (count < numCvElem)
        {
            // Cv_|bv|+2
            element_pow_zn(ct->Cv.Cv2, pp->h[idxCv], pr->st);
            element_printf("Cv2 = %B\n", ct->Cv.Cv2);
            element_init_G1(Cv_values[idxCv], pairing);
            element_set(Cv_values[idxCv], ct->Cv.Cv2);
            element_printf("Cv_values[%d] = %B\n", idxCv, Cv_values[idxCv]);
            idxCv++;
        }
    }
}

void CTUpdate(struct public_pars_type *pp, struct private_pars_type *pr1, struct private_pars_type *pr2, struct cipher_type *ct, struct cipher_type *ct2, char *t, char *t_prime)
{
    int time_period_id = (int)strtol(t, NULL, 2);
    int time_period_id2 = (int)strtol(t_prime, NULL, 2);
    To_prime = findTo(time_period_id2);
    element_t *bv;
    element_t *bv_prime;

    element_t h_pow_time;
    element_t g_pow_st, Fu_pow_st;
    element_init_G1(g_pow_st, pairing);
    element_init_G1(Fu_pow_st, pairing);
    element_init_Zr(pr2->st, pairing);
    element_random(pr2->st);
    element_init_G1(h_pow_time, pairing);

    // Find prefix bv
    char *prefix;
    int bvlen;
    for (int i = 0; i < num_of_to_element(time_period_id); i++)
    {
        for (int j = 0; j < num_of_to_element(time_period_id2); j++)
        {
            if (isPrefix(To[i], To_prime[j]) == 1)
            {
                printf("%s is prefix of %s\n", To[i], To_prime[j]);
                prefix = To[i];
                bvlen = strlen(To[i]);
                bv = malloc(bvlen * sizeof(element_t));
                for (int k = 0; k < bvlen; k++)
                {
                    element_init_Zr(bv[k], pairing);
                    element_set_si(bv[k], To[i][k] - 48);
                    element_printf("bv[%d] = %B\n", k, bv[k]);
                }
            }
        }
    }

    int bvplen = strlen(t_prime);
    printf("bvlen = %d\n", bvlen);
    bv_prime = malloc(bvplen * sizeof(element_t));
    int t_prime_digit[DEPTH];
    binStr2Digit(t_prime_digit, t_prime);
    for (int i = 0; i < bvplen; i++)
    {
        element_init_Zr(bv_prime[i], pairing);
        element_set_si(bv_prime[i], t_prime_digit[i]);
        element_printf("bv_prime[%d] = %B\n", i, bv_prime[i]);
    }

    element_init_GT(ct2->C0, pairing);
    element_init_G1(ct2->C1, pairing);
    element_init_G1(ct2->C2, pairing);
    element_init_G1(ct2->Cv.Cv0, pairing);

    element_t e_g1g2_pow_st;
    element_init_GT(e_g1g2_pow_st, pairing);
    element_pairing(e_g1g2_pow_st, pp->g1, pp->g2);
    element_pow_zn(e_g1g2_pow_st, e_g1g2_pow_st, pr2->st);

    element_t s_pow;
    element_init_Zr(s_pow, pairing);
    element_add(s_pow, pr1->st, pr2->st);

    // C0'
    element_mul(ct2->C0, ct->C0, e_g1g2_pow_st);
    element_printf("C0' = %B\n", ct2->C0);
    // C1'
    element_pow_zn(g_pow_st, pp->g, pr2->st);
    element_invert(g_pow_st, g_pow_st);
    element_mul(ct2->C1, ct->C1, g_pow_st);
    element_printf("C1' = %B\n", ct2->C1);
    // C2'
    element_pow_zn(Fu_pow_st, pr1->Fu, pr2->st);
    element_mul(ct2->C2, ct->C2, Fu_pow_st);
    element_printf("C2' = %B\n", ct2->C2);

    // Cv
    element_t C_pow;
    element_init_G1(C_pow, pairing);

    int index = getOffsetCv(To, prefix, num_of_to_element((int)strtol(t, NULL, 2)));
    element_printf("Cv_values[%d] = %B\n", index, Cv_values[index]);
    element_set(ct2->Cv.Cv0, Cv_values[index]);
    element_printf("Cv = %B\n", ct2->Cv.Cv0);
    int numCvElem = getNumEleCv(To, num_of_to_element(time_period_id));
    printf("numCvElem = %d\n", numCvElem);
    for (int i = index + 1; i < numCvElem; i++)
    {
        element_printf("Cv_values[%d] = %B\n", i, Cv_values[i]);
        element_printf("bv_prime[%d] = %B\n", i - 1, bv_prime[i - 1]);
        element_pow_zn(C_pow, Cv_values[i], bv_prime[i - 1]);
        element_printf("C_pow = %B\n", C_pow);
        element_mul(ct2->Cv.Cv0, ct2->Cv.Cv0, C_pow);
        element_printf("Cv = %B\n", ct2->Cv.Cv0);
    }

    element_t h_mul;
    element_init_G1(h_mul, pairing);
    element_set(h_mul, pp->h[0]);
    for (int i = 0; i < bvplen; i++)
    {
        element_pow_zn(h_pow_time, pp->h[i + 1], bv_prime[i]);
        element_mul(h_mul, h_mul, h_pow_time);
    }
    element_pow_zn(h_mul, h_mul, pr2->st);

    element_mul(ct2->Cv.Cv0, ct2->Cv.Cv0, h_mul);
    element_printf("Cv = %B\n", ct2->Cv.Cv0);
}

void Decrypt(struct cipher_type *ct, struct decrypt_key_type *dk, char *t, element_t key)
{
    element_t eC1DK1, eC2DK2, eCtDKt;
    element_init_GT(eC1DK1, pairing);
    element_init_GT(eC2DK2, pairing);
    element_init_GT(eCtDKt, pairing);

    element_pairing(eC1DK1, ct->C1, dk->DK1);
    element_pairing(eC2DK2, ct->C2, dk->DK2);
    element_pairing(eCtDKt, ct->Cv.Cv0, dk->DK3);

    element_t temp1, temp2;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_mul(temp1, ct->C0, eC1DK1);
    element_mul(temp2, eC2DK2, eCtDKt);

    element_printf("C0 = %B\n", ct->C0);
    element_printf("C1 = %B\n", ct->C1);
    element_printf("DK1 = %B\n", dk->DK1);
    element_printf("eC1DK1 = %B\n", eC1DK1);
    element_printf("C2 = %B\n", ct->C2);
    element_printf("DK2 = %B\n", dk->DK2);
    element_printf("eC2DK2 = %B\n", eC2DK2);
    element_printf("Cvt = %B\n", ct->Cv.Cv0);
    element_printf("DKt = %B\n", dk->DK3);
    element_printf("eCtDKt = %B\n", eCtDKt);
    element_printf("temp1 = %B\n", temp1);
    element_printf("temp2 = %B\n", temp2);

    element_mul(key, temp1, temp2);
    element_printf("key after = %B\n", key);
}

void Revoke(char *rl[], char *nodeID)
{
    // find the end of the list
    int i = 0;
    while (rl[i] != NULL)
    {
        i++;
    }
    rl[i] = nodeID;
}

/*
============================================================================
                                OPENSSL FUNCTIONS
============================================================================
*/

void handleErrors()
{
    fprintf(stderr, "Error occurred.\n");
    exit(EXIT_FAILURE);
}

void encryptFile(const char *inputFileName, const char *outputFileName, const unsigned char *key)
{
    FILE *inputFile, *outputFile;
    unsigned char iv[AES_BLOCK_SIZE];
    EVP_CIPHER_CTX *ctx;
    int bytesRead, ciphertextLen;
    unsigned char plaintext[1024];
    unsigned char ciphertext[1024 + AES_BLOCK_SIZE];

    // Open the input file
    inputFile = fopen(inputFileName, "rb");
    if (!inputFile)
    {
        fprintf(stderr, "Error opening input file.\n");
        exit(EXIT_FAILURE);
    }

    // Open the output file
    outputFile = fopen(outputFileName, "wb");
    if (!outputFile)
    {
        fclose(inputFile);
        fprintf(stderr, "Error opening output file.\n");
        exit(EXIT_FAILURE);
    }

    // Generate a random initialization vector (IV)
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1)
    {
        fclose(inputFile);
        fclose(outputFile);
        handleErrors();
    }

    // Write the IV to the output file
    fwrite(iv, 1, AES_BLOCK_SIZE, outputFile);

    // Create and initialize the cipher context
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Read, encrypt, and write the file content
    while ((bytesRead = fread(plaintext, 1, sizeof(plaintext), inputFile)) > 0)
    {
        if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLen, plaintext, bytesRead) != 1)
        {
            fclose(inputFile);
            fclose(outputFile);
            EVP_CIPHER_CTX_free(ctx);
            handleErrors();
        }
        fwrite(ciphertext, 1, ciphertextLen, outputFile);
    }

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertextLen) != 1)
    {
        fclose(inputFile);
        fclose(outputFile);
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    fwrite(ciphertext, 1, ciphertextLen, outputFile);

    // Clean up
    fclose(inputFile);
    fclose(outputFile);
    EVP_CIPHER_CTX_free(ctx);
}

void decryptFile(const char *inputFileName, const char *outputFileName, const unsigned char *key)
{
    FILE *inputFile, *outputFile;
    unsigned char iv[AES_BLOCK_SIZE];
    EVP_CIPHER_CTX *ctx;
    int bytesRead, plaintextLen;
    unsigned char ciphertext[1024 + AES_BLOCK_SIZE];
    unsigned char plaintext[1024];

    // Open the input file
    inputFile = fopen(inputFileName, "rb");
    if (!inputFile)
    {
        fprintf(stderr, "Error opening input file.\n");
        exit(EXIT_FAILURE);
    }

    // Open the output file
    outputFile = fopen(outputFileName, "wb");
    if (!outputFile)
    {
        fclose(inputFile);
        fprintf(stderr, "Error opening output file.\n");
        exit(EXIT_FAILURE);
    }

    // Read the IV from the input file
    if (fread(iv, 1, AES_BLOCK_SIZE, inputFile) != AES_BLOCK_SIZE)
    {
        fclose(inputFile);
        fclose(outputFile);
        fprintf(stderr, "Error reading IV from input file.\n");
        exit(EXIT_FAILURE);
    }

    // Create and initialize the cipher context
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Read, decrypt, and write the file content
    while ((bytesRead = fread(ciphertext, 1, sizeof(ciphertext), inputFile)) > 0)
    {
        if (EVP_DecryptUpdate(ctx, plaintext, &plaintextLen, ciphertext, bytesRead) != 1)
        {
            fclose(inputFile);
            fclose(outputFile);
            EVP_CIPHER_CTX_free(ctx);
            printf("Checkpoint 1.\n");
            handleErrors();
        }
        fwrite(plaintext, 1, plaintextLen, outputFile);
    }

    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext, &plaintextLen) != 1)
    {
        fclose(inputFile);
        fclose(outputFile);
        EVP_CIPHER_CTX_free(ctx);
        printf("Checkpoint 2.\n");
        handleErrors();
    }
    fwrite(plaintext, 1, plaintextLen, outputFile);

    // Clean up
    fclose(inputFile);
    fclose(outputFile);
    EVP_CIPHER_CTX_free(ctx);
}

void calculate_sha256(const char *input, unsigned char *output)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    // Create a new message digest context
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        fprintf(stderr, "Error creating MD context\n");
        return;
    }

    // Set the digest type to SHA-256
    md = EVP_sha256();

    // Initialize the message digest context
    EVP_DigestInit_ex(mdctx, md, NULL);

    // Update the digest context with the input data
    EVP_DigestUpdate(mdctx, input, strlen(input));

    // Finalize the hash and obtain the result
    EVP_DigestFinal_ex(mdctx, output, &md_len);

    // Clean up the message digest context
    EVP_MD_CTX_free(mdctx);
}

/*
============================================================================
                                    MAIN
============================================================================
*/

int main(int argc, char **argv)
{
    char *param =
        "type a\n"
        "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
        "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
        "r 730750818665451621361119245571504901405976559617\n"
        "exp2 159\n"
        "exp1 107\n"
        "sign1 1\n"
        "sign0 1\n";
    pairing_init_set_str(pairing, param);

    struct public_pars_type pubpar;
    struct private_pars_type pripar1;
    struct private_pars_type pripar2;
    struct key_update_type keyupd;
    struct decrypt_key_type deckey;
    struct cipher_type cipher;
    struct cipher_type cipher2;

    char *time_period;
    printf("time 1: ");
    scanf("%ms", &time_period);
    int time_digit[DEPTH];
    binStr2Digit(time_digit, time_period);

    char *time_period2;
    printf("time 2: ");
    scanf("%ms", &time_period2);
    int time_digit2[DEPTH];
    binStr2Digit(time_digit2, time_period2);

    char *user;
    printf("receiver: ");
    scanf("%ms", &user);
    int user_digit[DEPTH];
    binStr2Digit(user_digit, user);
    int user_id = strtol(user, NULL, 2);
    char **Path = findPath(user_id);

    // Nodes to be revoked
    Revoke(revokedList, "000");
    Revoke(revokedList, "001");
    Revoke(revokedList, "101");

    symtab_init(gDict);
    symtab_init(skDict);
    symtab_init(kuDict);

    /*
        Encrypt M using SHA-256
    */
    // Random message
    element_t random_message;
    element_init_GT(random_message, pairing);
    element_random(random_message);
    element_printf("Random message = %B\n", random_message);

    // Convert the GT element message to a string
    char random_message_str[4096]; // Adjust the buffer size as needed
    element_to_bytes((unsigned char *)random_message_str, random_message);

    // Define the hash variable
    unsigned char sha256_output[EVP_MAX_MD_SIZE];

    // Calculate the SHA-256 hash
    calculate_sha256(random_message_str, sha256_output);
    printf("SHA-256 Hash: ");
    for (int i = 0; i < EVP_MAX_MD_SIZE; i++)
    {
        printf("%02x", sha256_output[i]);
    }
    printf("\n");

    /*
        Encrypt the file with hashed random message
    */
    const char *inputFileName = "input.txt";
    const char *encryptedFileName = "encrypted_output.enc";

    OpenSSL_add_all_algorithms();

    encryptFile(inputFileName, encryptedFileName, sha256_output);
    printf("\n\nFile encrypted successfully.\n");

    // Convert the hash to a GT element for RS-IBE calculation
    element_t key_before;
    element_init_GT(key_before, pairing);
    element_from_bytes(key_before, sha256_output);
    element_printf("key before = %B\n", key_before);

    /*
        Start RS-IBE encryption
    */
    printf("\n\nSetup\n");
    Setup(&pubpar);

    printf("\n\nFuncDef\n");
    FuncDef(user, time_period, &pubpar, &pripar1);

    printf("\n\nSKGen\n");
    SKGen(&pubpar, &pripar1, Path);

    struct node headY = {"Y", NULL};
    struct node *KUNodes = findKUNodes(&headY, time_period, revokedList);

    printf("\n\nEncrypt\n");
    Encrypt(&pubpar, &pripar1, &cipher, time_period, key_before);

    /*
        At a different time t
    */
    printf("\n\n========== New time period t' ==========\n");
    printf("time 2: %s\n", time_period2);

    // Check if user is in RL
    int i = 0;
    while (revokedList[i] != NULL)
    {
        if (strcmp(user, revokedList[i]) == 0)
        {
            fprintf(stderr, "Error occcured. User is revoked!\n");
            exit(EXIT_FAILURE);
        }
        i++;
    }

    printf("\n\nFuncDef\n");
    FuncDef(user, time_period2, &pubpar, &pripar2);

    printf("\n\nSKGen\n");
    SKGen(&pubpar, &pripar2, Path);

    struct node headY2 = {"Y", NULL};
    struct node *KUNodes2 = findKUNodes(&headY2, time_period2, revokedList);

    printf("\n\nKeyUpdate\n");
    KeyUpdate(&pubpar, &pripar2, time_period2, KUNodes2);

    printf("\n\nDKGen\n");
    DKGen(&pubpar, &pripar2, &deckey, user, Path, KUNodes2);

    element_t key_after;
    element_init_GT(key_after, pairing);

    printf("\n\nCTUpdate\n");
    CTUpdate(&pubpar, &pripar1, &pripar2, &cipher, &cipher2, time_period, time_period2);

    printf("\n\nDecrypt\n");
    Decrypt(&cipher2, &deckey, time_period2, key_after);

    char key_before_str[4096];
    char key_after_str[4096]; // Adjust the buffer size as needed
    element_to_bytes((unsigned char *)key_after_str, key_after);
    printf("\n\n");
    element_printf("key before = %B\n", key_before);
    element_printf("key after = %B\n", key_after);

    // Verify signature
    if (strcmp(key_before_str, key_after_str))
    {
        printf("\n\nSignature verifies.\n");
    }
    else
    {
        printf("\n\nSignature does not verifies.\n");
    }

    free(time_period);
    free(time_period2);
    free(user);

    /*
        Decrypt a file using message as the key
    */
    const char *decryptedFileName = "decrypted_output.txt";

    OpenSSL_add_all_algorithms();

    // Decrypt the file
    decryptFile(encryptedFileName, decryptedFileName, key_after_str);
    printf("File decrypted successfully.\n");
}