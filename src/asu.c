/*
 ============================================================================
 Name        : asu.c
 Author      : lsc
 Version     :
 Copyright   : R & D Center of Internet of Things Security
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "asu.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CACERTF  HOME "demoCA/cacert.pem"
#define CAKEYF  HOME "demoCA/private/cakey.pem"
#define SERVERCERTF  HOME "demoCA/newcerts/usercert1.pem"
#define SERVERKEYF  HOME "userkey1.pem"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define PrivKey_PWD "111111" //server private key password

int count=0;

typedef struct user
{
    int user_ID;
    int client_socket;
    //client_socket==NOT_LOGIN,表示没有用户登录,
    //client_socket==NOT_IN_USE,表示没有用户注册,
}user;

//多线程共享user_table
static user user_table[USER_AMOUNT_MAX];
//访问user_table时要使用的信号量
pthread_mutex_t user_table_mutex;


void CA_initial()
{
	//create the directory of CA
	system("mkdir -p ./demoCA/newcerts/");
	system("mkdir -p ./demoCA/private/");
	system("touch ./demoCA/index.txt");
	system("echo 01 > ./demoCA/serial");

	//build CA,generate CA's RSA key-pair,password is wlwaq123
	system(
			"openssl genrsa -des3 -out ./demoCA/private/cakey.pem 1024 -passout pass:wlwaq123");
	//generate CA's cert request,and self-signed certificate
	system(
			"openssl req -new -x509 -days 365 -key ./demoCA/private/cakey.pem -out ./demoCA/cacert.pem");
}

void generate_keypair_and_certrequest(int userID)
{
	//generate user's RSA key-pair,password is 111111
	char tempcmd[70];
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	sprintf(tempcmd,
			"openssl genrsa -des3 -out userkey%d.pem 512 -passout pass:%s",
			userID, PrivKey_PWD);
	//printf("tempcmd is %s\n",tempcmd);
	system(tempcmd);
	//generate user's cert request,require the value of some attributes are the same as CA
	sprintf(tempcmd,
			"openssl req -new -days 365 -key userkey%d.pem -out userreq%d.pem",
			userID, userID);
	system(tempcmd);
}

BOOL CA_sign_cert(int userID)
{
	FILE *stream;
	char usercername[30], currentdir[50], tempstring[120];
	memset(usercername, '\0', sizeof(usercername)); //初始化usercername,以免后面写如乱码到文件中
	memset(tempstring, '\0', sizeof(tempstring)); //初始化tempstring,以免后面写如乱码到文件中
	memset(currentdir, '\0', sizeof(currentdir)); //初始化tempstring,以免后面写如乱码到文件中
	stream = popen("pwd", "r"); //get current directory
	fread(currentdir, sizeof(char), sizeof(currentdir), stream); //将刚刚FILE* stream的数据流读取到currentdir
	currentdir[strlen(currentdir) - 1] = '\0';
	sprintf(usercername, "userreq%d.pem", userID);

	sprintf(tempstring,
			"openssl ca -in userreq%d.pem -out %s/demoCA/newcerts/usercert%d.pem",
			userID, currentdir, userID);     //基于c语言调用openssl的shell指令
	int err = system(tempstring);

	if (err < 0)
		return FALSE;

	memset(tempstring, '\0', sizeof(tempstring));   //初始化tempstring,以免后面写如乱码到文件中
//	sprintf(tempstring, "rm -r %s", usercername);  //删除客户端用户证书请求文件(userreq%d.pem)
//	system(tempstring); //指令执行删除操作
	return TRUE;
	//}
}

void init_user_table()
{
    int i=0;
    for(i=0;i<USER_AMOUNT_MAX;i++)
    {
        user_table[i].client_socket = NOT_IN_USE;
        user_table[i].user_ID = 255;
    }
}

int init_server_socket()
{
    struct sockaddr_in server_addr;

    // 接收缓冲区
    int nRecvBuf = 32*1024; //设置为32K
    //发送缓冲区
    int nSendBuf = 32*1024; //设置为32K

    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);
    server_addr.sin_port = htons(CHAT_SERVER_PORT);

    int server_socket = socket(AF_INET,SOCK_STREAM,0);

    setsockopt(server_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(server_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));



    if( server_socket < 0)
    {
        printf("Create Socket Failed!");
        exit(1);
    }

    if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
    {
        printf("Server Bind Port : %d Failed!", CHAT_SERVER_PORT);
        exit(1);
    }

    if ( listen(server_socket, 5) )
    {
        printf("Server Listen Failed!");
        exit(1);
    }
    return server_socket;
}

EVP_PKEY *getpubkeyfromcert(int certnum)
{
	EVP_PKEY *pubKey;

	BIO * key = NULL;
	X509 * Cert = NULL; //X509证书结构体，保存CA证书
	key = BIO_new(BIO_s_file());

	char certname[60];
	memset(certname, '\0', sizeof(certname)); //初始化certname,以免后面写如乱码到文件中
	if (certnum == 0)
		sprintf(certname, "./demoCA/cacert.pem"); //./demoCA/
	else
		sprintf(certname, "./demoCA/newcerts/usercert%d.pem", certnum);

	BIO_read_filename(key,certname);
	if (!PEM_read_bio_X509(key, &Cert, 0, NULL))
	{
		/* Error 读取证书失败！*/
		printf("读取证书失败!\n");
		return NULL;
	}

	pubKey = EVP_PKEY_new();
	//获取证书公钥
	pubKey = X509_get_pubkey(Cert);
	return pubKey;
}


BOOL verify_sign(certificate_auth_requ receive_buffer,EVP_PKEY * aepubKey)
{
	EVP_MD_CTX mdctx;		 //摘要算法上下文变量

	EVP_MD_CTX_init(&mdctx); //初始化摘要上下文

	BYTE buffer[10000];
	WORD sign_input_len;

	sign_input_len = sizeof(receive_buffer.wai_packet_head)
			+ sizeof(receive_buffer.addid) + sizeof(receive_buffer.aechallenge)
			+ sizeof(receive_buffer.asuechallenge)
			+ sizeof(receive_buffer.staaecer)
			+ sizeof(receive_buffer.staasuecer);

	memcpy(buffer, (BYTE *) &receive_buffer, sign_input_len);

	if (!EVP_VerifyInit_ex(&mdctx, EVP_md5(), NULL))	//验证初始化，设置摘要算法，一定要和签名一致。
	{
		printf("EVP_VerifyInit_ex err\n");
		EVP_PKEY_free(aepubKey);
		//return false;
	}

	if (!EVP_VerifyUpdate(&mdctx, buffer, sign_input_len))	//验证签名（摘要）Update
	{
		printf("err\n");
		EVP_PKEY_free(aepubKey);
		//return false;
	}

	if (!EVP_VerifyFinal(&mdctx, receive_buffer.aesign.sign.data,
			receive_buffer.aesign.sign.length, aepubKey))		//验证签名（摘要）Update
			{
		printf("EVP_Verify err\n");
		EVP_PKEY_free(aepubKey);
		//return false;
	} else {
		printf("验证签名正确!!!\n");
	}
	//释放内存
//	EVP_PKEY_free (aepubKey);
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

int X509_Cert_Verify(int aecertnum, int asuecertnum)
{
	char tempcmd[200];
	FILE* fp;
	int i;

	char * ERRresult = "error";
	char * pae = NULL;
	char * pasue = NULL;

	//验证AE证书
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	sprintf(tempcmd,
			"openssl verify -CAfile ./demoCA/cacert.pem -verbose ./demoCA/newcerts/usercert%d.pem > X509_Cert_Verify_AE.txt",
			aecertnum);

	system(tempcmd);
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	fp = fopen("X509_Cert_Verify_AE.txt", "rb");
	if (fp == NULL )
	{
		printf("reading the cert file failed!\n");
	}
	i = fread(tempcmd, 1, 200, fp);
	pae = strstr(tempcmd, ERRresult);
	if (!pae)
		printf("验证AE证书正确！\n");
	else
	{
		printf("证书AE验证错误！\n");
		printf("错误信息：%s\n", tempcmd);

	}
	fclose(fp);

	//验证ASUE证书
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	sprintf(tempcmd,
			"openssl verify -CAfile ./demoCA/cacert.pem -verbose ./demoCA/newcerts/usercert%d.pem > X509_Cert_Verify_ASUE.txt",
			asuecertnum);
	system(tempcmd);
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	fp = fopen("X509_Cert_Verify_ASUE.txt", "rb");
	if (fp == NULL ) {
		printf("reading the cert file failed!\n");
	}
	fread(tempcmd, 1, 200, fp);
	pasue = strstr(tempcmd, ERRresult);
	if (!pasue)
		printf("验证ASUE证书正确！\n");
	else
	{
		printf("证书ASUE验证错误！\n");
		printf("错误信息：%s", tempcmd);
	}
	fclose(fp);

	printf("verify end!!!\n");

	if (!pae && !pasue)
		return AE_OK_ASUE_OK;      //AE和ASUE证书验证都正确
	else if (!pae && pasue)
		return AE_OK_ASUE_ERROR;   //AE证书验证正确，ASUE证书验证错误
	else if (pae && !pasue)
		return AE_ERROR_ASUE_OK;   //AE证书验证错误，AE证书验证正确
}


//ASU从cakey.pem中提取CA的私钥，以便后续进行ASU的签名
EVP_PKEY * getprivkeyfromprivkeyfile()
{
	EVP_PKEY * privKey;
	FILE* fp;
	RSA* rsa;

	fp = fopen("./demoCA/private/cakey.pem", "r");

	if (fp == NULL)
	{
		fprintf(stderr, "Unable to open %s for RSA priv params\n", "./demoCA/pricate/cakey.pem");
		return NULL;
	}
	printf("123456");
	if ((rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL)) == NULL)
	{
		fprintf(stderr, "Unable to read private key parameters\n");
		return NULL;
	}
	printf("654321");
	fclose(fp);

	// print
	printf("Content of CA's Private key PEM file\n");
	RSA_print_fp(stdout, rsa, 0);
	printf("\n");

	privKey = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(privKey, rsa) != 1) //保存RSA结构体到EVP_PKEY结构体
	{
		printf("EVP_PKEY_set1_RSA err\n");
		RSA_free (rsa);
		return NULL;
	} else
	{
		RSA_free (rsa);
		return privKey;
	}
}

BOOL gen_sign(int user_ID, BYTE * input,int inputLength,BYTE * sign_value, unsigned int *sign_len,EVP_PKEY * privKey)
{
	EVP_MD_CTX mdctx;						//摘要算法上下文变量

	unsigned int temp_sign_len;
	unsigned int i;

	//以下是计算签名代码
	EVP_MD_CTX_init(&mdctx);				//初始化摘要上下文

	if (!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))	//签名初始化，设置摘要算法，本例为MD5
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	if (!EVP_SignUpdate(&mdctx, input, inputLength))	//计算签名（摘要）Update
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	if (!EVP_SignFinal(&mdctx, sign_value, & temp_sign_len, privKey))	//签名输出
	{
		printf("err\n");
		EVP_PKEY_free (privKey);
		return FALSE;
	}

	* sign_len = temp_sign_len;

	printf("签名值是: \n");
	for (i = 0; i < * sign_len; i++)
	{
		if (i % 16 == 0)
			printf("\n%08xH: ", i);
		printf("%02x ", sign_value[i]);
	}
	printf("\n");
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

int gen_certificate_auth_resp_packet(certificate_auth_requ receive_buffer)
{
	certificate_auth_resp send_buffer;
	EVP_PKEY *aepubKey = NULL;
	unsigned char *pTmp = NULL;
	int aepubkeyLen;
	int i,CertVerifyResult;
	unsigned char deraepubkey[1024];

	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	aepubKey = getpubkeyfromcert(2);



	pTmp = deraepubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);
	printf("ae's PublicKey is: \n");
	for (i = 0; i < aepubkeyLen; i++)
	{
		printf("%02x", deraepubkey[i]);
	}
	printf("\n");

	if (verify_sign(receive_buffer, aepubKey))
	{
		printf("验证签名正确......\n");
		printf("%d\n",count);
		count++;
		EVP_PKEY_free(aepubKey);
	}

	CertVerifyResult = X509_Cert_Verify(2,1);

	if(CertVerifyResult == AE_OK_ASUE_OK)
	{
		send_buffer.cervalidresult.cerresult1 = 0;   //ASUE证书验证正确有效
		send_buffer.cervalidresult.cerresult2 = 0;   //AE证书验证正确有效
	}
	else if(CertVerifyResult == AE_OK_ASUE_ERROR)
	{
		send_buffer.cervalidresult.cerresult1 = 1;   //ASUE证书验证错误无效
		send_buffer.cervalidresult.cerresult2 = 0;   //AE证书验证正确有效
	}
	else if(CertVerifyResult == AE_ERROR_ASUE_OK)
	{
		send_buffer.cervalidresult.cerresult1 = 0;   //ASUE证书验证正确有效
		send_buffer.cervalidresult.cerresult2 = 1;   //AE证书验证错误无效
	}

	send_buffer.wai_packet_head.version = 1;
	send_buffer.wai_packet_head.type = 1;
	send_buffer.wai_packet_head.subtype = 5;
	send_buffer.wai_packet_head.reserved = 0;
	send_buffer.wai_packet_head.packetnumber = 4;
	send_buffer.wai_packet_head.fragmentnumber = 0;
	send_buffer.wai_packet_head.identify = 0;


	bzero((send_buffer.addid.mac1),sizeof(send_buffer.addid.mac1));
	bzero((send_buffer.addid.mac2),sizeof(send_buffer.addid.mac2));

	send_buffer.cervalidresult.type = 2; /* 证书验证结果属性类型 (2)*/
	send_buffer.cervalidresult.length = sizeof(send_buffer.cervalidresult.random1)+sizeof(send_buffer.cervalidresult.random2)
			+sizeof(send_buffer.cervalidresult.cerresult1)+sizeof(send_buffer.cervalidresult.certificate1)
			+sizeof(send_buffer.cervalidresult.cerresult2)+sizeof(send_buffer.cervalidresult.certificate2);

	bzero((send_buffer.cervalidresult.random1),sizeof(send_buffer.cervalidresult.random1));
	bzero((send_buffer.cervalidresult.random2),sizeof(send_buffer.cervalidresult.random2));


	send_buffer.wai_packet_head.length = sizeof(send_buffer.wai_packet_head)+sizeof(send_buffer.addid)
			+sizeof(send_buffer.cervalidresult)+sizeof(send_buffer.asusign);


	//ASU使用CA的私钥(cakey.pem)来生成CA签名
	privKey = getprivkeyfromprivkeyfile();
	if (privKey == NULL )
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}
	if (!gen_sign(0, (BYTE *)&send_buffer,send_buffer.wai_packet_head.length-sizeof(send_buffer.asusign),sign_value, &sign_len, privKey))
	{
		printf("签名失败！");
	}


	send_buffer.asusign.sign.length = sign_len;
	memcpy(send_buffer.asusign.sign.data, sign_value, sign_len);

	return SUCCEED;







	return 2; /* 证书验证结果属性类型 (2)*/
}





//int process_request(int client_socket, BYTE * receive_buffer)
//{
//	certificate_auth_resp send_buffer;
//
//	int userID;
//
//
//    bzero((BYTE *)&send_buffer,sizeof(send_buffer));
//
//
//
//    sign_attribute aesign = ((certificate_auth_requ *)receive_buffer)->aesign;
//    addindex addid = ((certificate_auth_requ *)receive_buffer)->addid;
//    BYTE * asuechallenge = ((certificate_auth_requ *)receive_buffer)->asuechallenge;
//    BYTE * aechallenge = ((certificate_auth_requ *)receive_buffer)->aechallenge;
//    certificate staasuecer = ((certificate_auth_requ *)receive_buffer)->staasuecer;
//    certificate staaecer = ((certificate_auth_requ *)receive_buffer)->staaecer;
//
//    printf("Request %s from client\n",((certificate_auth_requ *)receive_buffer)->addid);
//    switch(((certificate_auth_requ *)receive_buffer)->wai_packet_head.subtype)
//    {
//	case CERTIFICATE_AUTH_REQU:
//		send_buffer.cervalidresult.type = gen_certificate_auth_resp_packet(certificate_auth_requ receive_buffer);
//		break;
//	case REQUEST_CERTIFICATE:
//		CA_sign_cert(userID);
////		send_buffer.cervalidresult.type = gen_certificate_auth_resp_packet(client_socket);
//		break;
////	case REQUEST_CERTIFICATE:
////		CA_sign_cert(userID);
////		send_buffer.cervalidresult.type = gen_certificate_auth_resp_packet(client_socket);
//		break;
//    }
//    printf("Answer %d (certificate_valid_result) to client\n",send_buffer.cervalidresult.type);
//    send(client_socket, (certificate_auth_resp *)&send_buffer,sizeof(send_buffer),0);
//    return send_buffer.cervalidresult.type;
//}



void * talk_to_client(void * new_server_socket_to_client)
{
	int i,type;
	int new_server_socket = (int)new_server_socket_to_client;
	int request = NO_COMMAND;
//	while (request != EXIT)
//	{
		certificate_auth_requ buffer;
		bzero((BYTE *) &buffer, sizeof(buffer));
		int length = recv(new_server_socket, (BYTE *) &buffer, sizeof(buffer),0);

		printf("\n----------------------------------------------------------------------------------\n");

		printf("server receive %d data from client!!!!!!!!!!!!!!!!!!!!!!!!!\n", length);

		if(length == 9586)
		{
			printf("服务器接收到客户端%d字节的有效证书认证请求分组数据包\n", length);
//			printf("%s\n", buffer.staasuecer.cer_X509);
//			printf("%s\n", buffer.staaecer.cer_X509);
		}


		printf("****************************************************************************\n");

		if(buffer.aesign.sign.length != 0)
		{
			printf("签名数据内容长度为%d字节\n",buffer.aesign.sign.length);
			printf("签名数据内容是: \n");
			for (i = 0; i < buffer.aesign.sign.length; i++)
			{
				if (i % 16 == 0)
					printf("\n%08xH: ", i);
				printf("%02x ", buffer.aesign.sign.data[i]);
			}
			printf("\n");
		}

		if (length < 0)
		{
			printf("Server Recieve Data Failed!\n");
			close(new_server_socket);
			pthread_exit(NULL);
		}
		if (length == 0)
		{
			close(new_server_socket);
			pthread_exit(NULL);
		}


		type = gen_certificate_auth_resp_packet(buffer);





		//request = process_request(new_server_socket, (char*) &buffer);
//	}
	close(new_server_socket);
	pthread_exit(NULL);


}


int main()
{
	init_user_table();
	pthread_mutex_init(&user_table_mutex, NULL);
	int server_socket = init_server_socket();

	pthread_t child_thread;
	pthread_attr_t child_thread_attr;
	pthread_attr_init(&child_thread_attr);
	pthread_attr_setdetachstate(&child_thread_attr, PTHREAD_CREATE_DETACHED);

	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);
		int new_server_socket = accept(server_socket,
				(struct sockaddr*) &client_addr, &length);
		if (new_server_socket < 0)
		{
			printf("Server Accept Failed!\n");
			break;
		}
		if (pthread_create(&child_thread, &child_thread_attr, talk_to_client,(void *) new_server_socket) < 0)
			printf("pthread_create Failed : %s\n", strerror(errno));
	}


}
