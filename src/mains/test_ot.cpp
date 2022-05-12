
#include <unistd.h>
#include <getopt.h>
#include <string>
#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../util/ot/naor-pinkas.h"
//#include "../util/helpers.h"
#include "../util/connection.h"
#include "../util/socket.h"

const uint8_t test_seed[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

int32_t main(int32_t argc, char **argv)
{

    uint32_t symsecbits = 128, i, j, ntasks = 1;
    string address = "127.0.0.1";
    uint16_t port = 7766;

    crypto crypto(symsecbits, (uint8_t *)test_seed);

    vector<CSocket> sockfd(ntasks + 1);
    role_type role = (role_type)0;

    int ch;
    while ((ch = getopt(argc, argv, "r:")) != -1)
    {
        switch (ch)
        {
        case 'r':
            printf("option :'%s'\n", optarg);
            if (0 == strcmp(optarg, "0"))
            {
                role = SERVER;
            }
            else
            {
                role = CLIENT;
            }
            break;
        default:
            printf("other option : %c\n", ch);
        }
    }

    if (role == SERVER)
    {
        listen(address.c_str(), port, sockfd.data(), ntasks);
    }
    else
    {
        for (i = 0; i < ntasks; i++)
            connect(address.c_str(), port, sockfd[i]);
    }

    NaorPinkas *bot = new NaorPinkas(&crypto, ECC_FIELD);

    uint8_t ret_buf[1024] = {0};

    if (role == SERVER)
    {
        bot->Sender(2, 2, &sockfd[0], ret_buf);

        for (j = 0; j < 1024; j++)
        {
            /* code */
            cout << setw(2) << setfill('0') << (hex) << (int)ret_buf[j];
            if ((j+1)%32 == 0)
            {
                cout << endl;
            }            
        }
    }
    else
    {
        CBitVector choice(2);
        choice.SetBit(0, 0);
        choice.SetBit(1, 1);

        bot->Receiver(2, 2, choice, &sockfd[0], ret_buf);

        choice.delCBitVector();

        for (j = 0; j < 1024; j++)
        {
            /* code */
            cout << setw(2) << setfill('0') << (hex) << (int)ret_buf[j];
            if ((j+1)%32 == 0)
            {
                cout << endl;
            }
        }
    }

    delete bot;

    return 1;
}
