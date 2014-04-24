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
#include "logtest.h"

///* define HOME to be dir for key and cert files... */
//#define HOME "./"
///* Make these what you want for cert & key files */
//#define CACERTF  HOME "newcerts/cacert.pem"
//#define CAKEYF  HOME "private/cakey.pem"
//#define ASUECERTF  HOME "newcerts/usercert1.pem"
//#define AECERTF  HOME "newcerts/usercert2.pem"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }



static int count=1;  //作用：测试asu运行fill_certificate_auth_resp_packet函数的次数

typedef struct user
{
    BYTE user_ID[255];
    int client_socket;
    //client_socket==NOT_LOGIN,表示没有用户登录,
    //client_socket==NOT_IN_USE,表示没有用户注册,
}user;

//多线程共享user_table
static user user_table[USER_AMOUNT_MAX];
//访问user_table时要使用的信号量
pthread_mutex_t user_table_mutex;




/*************************************************

Function:    // CA_initial
Description: // CA(驻留在asu中)初始化：建立CA目录、文档，生成CA私钥和自签名证书
Calls:       // openssl指令
Called By:   // main()-the first time execution of asu.c;
Input:	     //	无
Output:      //	CA密钥文件、CA自签名证书
Return:      // void
Others:      // 基于c语言调用openssl的shell指令

*************************************************/
//void CA_initial()
//{
//	//create the directory of CA
//	system("mkdir -p ./demoCA/newcerts/");
//	system("mkdir -p ./demoCA/private/");
//	system("touch ./demoCA/index.txt");
//	system("echo 01 > ./demoCA/serial");
//
//	//build CA,generate CA's RSA key-pair,does not have password
//	system("openssl genrsa -out ./demoCA/private/cakey.pem 1024");
//	//generate CA's cert request,and self-signed certificate
//	//system("openssl req -new -x509 -days 365 -key ./demoCA/private/cakey.pem -out ./demoCA/cacert.pem");
//	system("openssl req -new -x509 -days 365 -key ./demoCA/private/cakey.pem -out ./demoCA/cacert.pem");
//}

void CA_initial()
{
	//create the directory of CA
	printf("***********************************************\n 1) create the directory of CA (demoCA):");
	system("mkdir -p ./demoCA/newcerts/");
	system("mkdir -p ./demoCA/private/");
	system("touch ./demoCA/index.txt");
	system("echo 01 > ./demoCA/serial");

	//build CA,generate CA's ECC key-pair,does not have password
	printf("***********************************************\n 2) build CA,generate CA's ECC key-pair:");
	system("openssl ecparam -out EccCAkey.pem -name prime256v1 -genkey");
	//generate CA's cert request,and self-signed certificate
	//system("openssl req -new -x509 -days 365 -key ./demoCA/private/cakey.pem -out ./demoCA/cacert.pem");
	printf("***********************************************\n 3) generate CA's cert request:");
	system("openssl req -key EccCAkey.pem -new -out EccCAreq.pem");

	printf("***********************************************\n 4) generate CA's self-signed certificate:");
	system("openssl x509 -req -in EccCAreq.pem -signkey EccCAkey.pem -out EccCAcert.pem");
}


/*************************************************

Function:    // generate_keypair_and_certrequest
Description: // 生成密钥对、数字证书签发请求文件
Calls:       // openssl指令
Called By:   // main();
Input:	     //	BYTE *userID-asu客户端的用户名(字符串)
Output:      //	asu客户端的密钥文件、数字证书签发请求文件
Return:      // void
Others:      // 基于c语言调用openssl的shell指令

*************************************************/

//void generate_keypair_and_certrequest(BYTE *userID)
//{
//
//	char tempcmd[200];
//	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写入乱码到文件中
//	//generate user's ECC key-pair,does not have password
//	sprintf(tempcmd,"openssl genrsa -out %skey.pem 512",userID);
//	system(tempcmd);
//
//	//generate user's cert request,require the value of some attributes are the same as CA
//	sprintf(tempcmd,"openssl req -new -days 365 -key %skey.pem -out %sreq.pem",userID, userID);
//	system(tempcmd);
//}

void generate_keypair_and_certrequest(BYTE *userID)
{

	char tempcmd[200];
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写入乱码到文件中
	//generate user's ECC key-pair,does not have password
	printf("***********************************************\n 5) generate user's ECC key-pair:");
	sprintf(tempcmd,"openssl ecparam -out Ecc%skey.pem -name prime256v1 -genkey",userID);
	system(tempcmd);

	//generate user's cert request,require the value of some attributes are the same as CA
	printf("***********************************************\n 6) generate user's cert request,require the value of some attributes are the same as CA:");
	sprintf(tempcmd,"openssl req -key Ecc%skey.pem -new -out Ecc%sreq.pem",userID, userID);
	system(tempcmd);
}

/*************************************************

Function:    // CA_sign_cert
Description: // CA(驻留在asu中)使用自己的私钥来为asu客户端签发数字证书
Calls:       // openssl指令
Called By:   // main();
Input:	     //	BYTE *userID-asu客户端的用户名(字符串)
Output:      //	asu客户端的密钥文件、数字证书签发请求文件
Return:      // TRUE-证书签发成功，FALSE-证书签发失败
Others:      // 基于c语言调用openssl的shell指令

*************************************************/

//BOOL CA_sign_cert(BYTE *userID)
//{
//	FILE *stream;
//	int err;
//	char usercername[30], currentdir[50], tempstring[200];
//	memset(usercername, '\0', sizeof(usercername)); //初始化usercername,以免后面写入乱码到文件中
//	memset(tempstring, '\0', sizeof(tempstring)); //初始化tempstring,以免后面写入乱码到文件中
//	memset(currentdir, '\0', sizeof(currentdir)); //初始化tempstring,以免后面写入乱码到文件中
//	stream = popen("pwd", "r"); //get current directory
//	fread(currentdir, sizeof(char), sizeof(currentdir), stream); //将刚刚FILE* stream的数据流读取到currentdir
//	currentdir[strlen(currentdir) - 1] = '\0';
//	sprintf(usercername, "%sreq.pem", userID);
//
//	sprintf(tempstring,"openssl ca -in %sreq.pem -out %s/demoCA/newcerts/%scert.pem",
//			userID, currentdir, userID);     //基于c语言调用openssl的shell指令
//
//	err = system(tempstring);
//	if (err < 0)
//		return FALSE;
//	else
//		return TRUE;
//}
BOOL CA_sign_cert(BYTE *userID)
{
	FILE *stream;
	int err;
	char usercername[30], currentdir[50], tempstring[200];
	memset(usercername, '\0', sizeof(usercername)); //初始化usercername,以免后面写入乱码到文件中
	memset(tempstring, '\0', sizeof(tempstring)); //初始化tempstring,以免后面写入乱码到文件中
	memset(currentdir, '\0', sizeof(currentdir)); //初始化tempstring,以免后面写入乱码到文件中
	stream = popen("pwd", "r"); //get current directory
	fread(currentdir, sizeof(char), sizeof(currentdir), stream); //将刚刚FILE* stream的数据流读取到currentdir
	currentdir[strlen(currentdir) - 1] = '\0';
	sprintf(usercername, "Ecc%sreq.pem", userID);

	printf("***********************************************\n 7) CA sign the user's cert, using CA's private key:");
	sprintf(tempstring,"openssl x509 -req -in %s -CA EccCAcert.pem -CAkey EccCAkey.pem -out %s/demoCA/newcerts/Ecc%scert.pem -CAcreateserial",
			usercername, currentdir, userID);     //基于c语言调用openssl的shell指令

	err = system(tempstring);
	if (err < 0 || (err == 256))
		return FALSE;
	else
		return TRUE;
}
//BOOL CA_sign_cert(BYTE *userID)
//{
//	FILE *stream;
//	int err;
//	char usercername[30], currentdir[50], tempstring[200];
//	memset(usercername, '\0', sizeof(usercername)); //初始化usercername,以免后面写入乱码到文件中
//	memset(tempstring, '\0', sizeof(tempstring)); //初始化tempstring,以免后面写入乱码到文件中
//	memset(currentdir, '\0', sizeof(currentdir)); //初始化tempstring,以免后面写入乱码到文件中
//	stream = popen("pwd", "r"); //get current directory
//	fread(currentdir, sizeof(char), sizeof(currentdir), stream); //将刚刚FILE* stream的数据流读取到currentdir
//	currentdir[strlen(currentdir) - 1] = '\0';
//	sprintf(usercername, "Ecc%s.req", userID);
//
//	sprintf(tempstring,"openssl x509 -req -in %s -CA EccCA.pem -CAkey EccCA.key -out %s/demoCA/newcerts/Ecc%scert.pem -CAcreateserial",
//			usercername, currentdir, userID);     //基于c语言调用openssl的shell指令
//
//	err = system(tempstring);
//	if (err < 0 || (err == 256))
//		return FALSE;
//	else
//		return TRUE;
//}
/*************************************************

Function:    // init_user_table
Description: // 初始化asu客户端列表
Calls:       // 无
Called By:   // main();
Input:	     //	无
Output:      //	初始化后的user_table全局变量(一维数组)
Return:      // void
Others:      // 为结构体成员赋初始值

*************************************************/
void init_user_table()
{
    int i=0;
    for(i=0;i<USER_AMOUNT_MAX;i++)
    {
        user_table[i].client_socket = NOT_IN_USE;
        memset(user_table[i].user_ID,0,sizeof(user_table[i].user_ID));
    }
}

/*************************************************

Function:    // init_server_socket
Description: // 初始化asu(扮演服务器角色)的server_socket
Calls:       // socket API
Called By:   // main();
Input:	     //	无
Output:      //	无
Return:      // server_socket
Others:      //

*************************************************/
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


int send_to_peer(int new_server_socket, BYTE *send_buffer, int send_len)
{

	int length = send(new_server_socket,send_buffer,send_len,0);
	printf("---- send %d bytes -----\n",length);

    if(length <0)
    {
        printf("Socket Send Data Failed Or Closed\n");
        close(new_server_socket);
        return FALSE;
    }
	else
		return TRUE;
}

int recv_from_peer(int new_server_socket, BYTE *recv_buffer, int recv_len)
{
	int length = recv(new_server_socket,recv_buffer, recv_len, MSG_WAITALL);
	
	if (length < 0)
	{
		printf("Receive Data From Server Failed\n");
		return FALSE;
	}else if(length < recv_len)
	{
		printf("Receive data from server less than required, %d bytes.\n", length);
		return FALSE;
	}else if(length > recv_len)
	{
		printf("Receive data from server more than required.\n");
		return FALSE;
	}
	else
	{
		printf("receive data succeed, %d bytes.\n",length);
		return TRUE;
	}

}


/*************************************************

Function:    // getpubkeyfromcert
Description: // 从数字证书(PEM文件)中读取公钥
Calls:       // openssl中读PEM文件的API
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	用户证书的用户名certnum
Output:      //	数字证书公钥
Return:      // EVP_PKEY *pubKey
Others:      // 用户证书的用户名certnum最好是用字符串形式，但是目前是int值，有待改进

*************************************************/
EVP_PKEY *getpubkeyfromcert(int certnum)
{
	EVP_PKEY *pubKey;

	BIO * key = NULL;
	X509 * Cert = NULL; //X509证书结构体，保存CA证书
	key = BIO_new(BIO_s_file());

	char certname[60];
	memset(certname, '\0', sizeof(certname)); //初始化certname,以免后面写如乱码到文件中
	if (certnum == 0)
		sprintf(certname, "./cacerts/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%d.pem", certnum);

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

/*************************************************

Function:    // verify_sign
Description: // 验证数字签名
Calls:       // openssl验证签名的API
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	input---待验证签名的整个数据包
                sign_input_len---待验证签名的有效数据字段的长度，并非整个input长度
                sign_value---签名字段
                sign_output_len---签名字段的长度
                pubKey---验证签名所使用的公钥
Output:      //	验证签名结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

*************************************************/

BOOL verify_sign(BYTE *input,int sign_input_len,BYTE * sign_value, unsigned int sign_output_len,EVP_PKEY * pubKey)
{
	EVP_MD_CTX mdctx;		 //摘要算法上下文变量

	EVP_MD_CTX_init(&mdctx); //初始化摘要上下文

	BYTE sign_input_buffer[10000];

	memcpy(sign_input_buffer,input,sign_input_len);    //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	if (!EVP_VerifyInit_ex(&mdctx, EVP_md5(), NULL))	//验证初始化，设置摘要算法，一定要和签名一致。
	{
		printf("EVP_VerifyInit_ex err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyUpdate(&mdctx, sign_input_buffer, sign_input_len))	//验证签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyFinal(&mdctx, sign_value,sign_output_len, pubKey))		//验证签名（摘要）Update
	{
		printf("EVP_Verify err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}
	else
	{
		printf("验证签名正确!!!\n");
	}
	//释放内存
//	EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

/*************************************************

Function:    // X509_Cert_Verify
Description: // X509证书验证
Calls:       // openssl证书验证指令verify
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	aecertnum---AE(NVR)数字证书编号
                asuecertnum---ASUE(摄像机或NVR客户端)数字证书编号
Output:      //	AE和ASUE数字证书的验证结果
Return:      // 宏AE_OK_ASUE_OK or AE_OK_ASUE_ERROR or AE_ERROR_ASUE_OK or AE_ERROR_ASUE_ERROR
Others:      // 关于证书验证操作既可以使用verify指令，也可以使用X509_verify_cert函数来实现，但是目前测试着使用X509_verify_cert函数总是出错，还有待于进一步研究

*************************************************/

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
			"openssl verify -CAfile ./cacert/cacert.pem -verbose ./cert/usercert%d.pem > X509_Cert_Verify_AE.txt",
			aecertnum);

	system(tempcmd);
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	fp = fopen("X509_Cert_Verify_AE.txt", "rb");
	if (NULL == fp)
	{
		printf("reading the cert file failed!\n");
	}
	i = fread(tempcmd, 1, 200, fp);
	pae = strstr(tempcmd, ERRresult);
	if (NULL == pae)
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
			"openssl verify -CAfile ./cacert/cacert.pem -verbose ./cert/usercert%d.pem > X509_Cert_Verify_ASUE.txt",
			asuecertnum);
	system(tempcmd);
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	fp = fopen("X509_Cert_Verify_ASUE.txt", "rb");
	if (NULL == fp)
	{
		printf("reading the cert file failed!\n");
	}
	fread(tempcmd, 1, 200, fp);
	pasue = strstr(tempcmd, ERRresult);
	if (NULL == pasue)
		printf("ASU验证ASUE证书正确！\n");
	else
	{
		printf("ASU证书ASUE验证错误！\n");
		printf("错误信息：%s", tempcmd);
	}
	fclose(fp);

	printf("ASU验证AE、ASUE证书结束!!!\n");

	if ((NULL==pae) && (NULL==pasue))
		return AE_OK_ASUE_OK;      //AE和ASUE证书验证都正确
	else if ((NULL==pae)&& (NULL!=pasue))
		return AE_OK_ASUE_ERROR;   //AE证书验证正确，ASUE证书验证错误
	else if ((NULL!=pae) && (NULL==pasue))
		return AE_ERROR_ASUE_OK;   //AE证书验证错误，ASUE证书验证正确
	else if ((NULL!=pae) && (NULL!=pasue))
		return AE_ERROR_ASUE_ERROR;   //AE证书验证错误，ASUE证书验证错误
	else
		return AE_ERROR_ASUE_ERROR;
}

/*************************************************

Function:    // getprivkeyfromprivkeyfile
Description: // CA(驻留在ASU中)从cakey.pem中提取CA的私钥，以便后续进行ASU的签名
Calls:       // openssl读取私钥PEM文件相关函数
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	无
Output:      //	CA(驻留在ASU中)的私钥
Return:      // EVP_PKEY *privKey
Others:      //

*************************************************/

EVP_PKEY * getprivkeyfromprivkeyfile(int userID)
{
	EVP_PKEY * privKey;
	FILE* fp;
	RSA* rsa;

	char keyname[40];

	if (userID == 0)
		sprintf(keyname, "./private/cakey.pem");                   //asu密钥文件
	else
		sprintf(keyname, "./private/userkey%d.pem", userID);       //ae或asue密钥文件
	fp = fopen(keyname, "r");

	if (NULL == fp)
	{
		fprintf(stderr, "Unable to open %s for RSA priv params\n", "./pricate/cakey.pem");
		return NULL;
	}

	rsa = RSA_new();
	if ((rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL)) == NULL)
	{
		fprintf(stderr, "Unable to read private key parameters\n");
		return NULL;
	}
	fclose(fp);

	// print
//	printf("Content of CA's Private key PEM file\n");
//	RSA_print_fp(stdout, rsa, 0);
//	printf("\n");

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

/*************************************************

Function:    // gen_sign
Description: // 生成数字签名
Calls:       // openssl生成签名的API
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	input---待生成签名的整个数据包(分组)
                sign_input_len---待生成签名的有效数据字段的长度，并非整个input长度
                sign_value---保存生成的字段
                sign_output_len---生成的签名字段的长度
                privKey---生成签名所使用的私钥
Output:      //	生成签名操作结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

*************************************************/

BOOL gen_sign(BYTE * input,int sign_input_len,BYTE * sign_value, unsigned int *sign_output_len,EVP_PKEY * privKey)
{
	EVP_MD_CTX mdctx;						//摘要算法上下文变量

	unsigned int temp_sign_len;
	unsigned int i;
	BYTE sign_input_buffer[10000];

	memcpy(sign_input_buffer,input,sign_input_len);    //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	//以下是计算签名代码
	EVP_MD_CTX_init(&mdctx);				//初始化摘要上下文

	if (!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))	//签名初始化，设置摘要算法，本例为MD5
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_SignUpdate(&mdctx, sign_input_buffer, sign_input_len))	//计算签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同;
		return FALSE;
	}

	if (!EVP_SignFinal(&mdctx, sign_value, & temp_sign_len, privKey))	//签名输出
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	* sign_output_len = temp_sign_len;

	printf("签名值是: \n");
	for (i = 0; i < * sign_output_len; i++)
	{
		if (i % 16 == 0)
			printf("\n%08xH: ", i);
		printf("%02x ", sign_value[i]);
	}
	printf("\n");
	//清理内存
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}


BOOL getCertData(int userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (userID == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%d.pem", userID);                //eclipse调试或运行

	printf("cert file name: %s\n", certname);

	fp = fopen(certname, "rb");
	if (fp == NULL)
	{
		printf("reading the cert file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
	printf("cert's length is %d\n", *len);
	fclose(fp);
	printf("将证书保存到缓存buffer成功!\n");

	return TRUE;
}













/*************************************************

Function:    // fill_certificate_auth_resp_packet
Description: // 按照认证协议中的证书认证响应分组格式来填充分组
Calls:       // getpubkeyfromcert，verify_sign，X509_Cert_Verify，getprivkeyfromprivkeyfile，gen_sign
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	input---待生成签名的整个数据包(分组)
                sign_input_len---待生成签名的有效数据字段的长度，并非整个input长度
                sign_value---保存生成的字段
                sign_output_len---生成的签名字段的长度
                privKey---生成签名所使用的私钥
Output:      //	生成签名操作结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      //

*************************************************/

int fill_certificate_auth_resp_packet(certificate_auth_requ *recv_certificate_auth_requ_buffer,certificate_auth_resp *send_certificate_auth_resp_buffer)
{
	//certificate_auth_resp certificate_auth_resp_buffer;    //待填充及发送的证书认证响应分组
	EVP_PKEY *aepubKey = NULL;
//	BYTE *pTmp = NULL;
//	int aepubkeyLen;
//	int i;
	int CertVerifyResult;
	//BYTE deraepubkey[1024];

	EVP_PKEY * privKey;

	BYTE cervalresasusign[1024];			     //保存ASU服务器对证书验证结果字段的签名值的数组
	unsigned int  cervalresasusignlen;           //保存ASU服务器对证书验证结果字段的签名值数组的长度

	BYTE cerauthrespasusign[1024];			     //保存ASU服务器对整个证书认证响应分组(除本字段外)的签名值的数组
	unsigned int  cerauthrespasusignlen;         //保存ASU服务器对整个证书认证响应分组(除本字段外)的签名值数组的长度


	BYTE cert_buffer[5000];
	int cert_len = 0;
	int aecertcheck,asuecertcheck;

	//2号证书文件-ae数字证书文件，
	//今后需要根据recv_certificate_auth_requ_buffer->staasuecer.cer_identify字段值来提取证书文件的编号等信息
	aepubKey = getpubkeyfromcert(2);
	if(aepubKey == NULL)
	{
		printf("getpubkeyfromcert.....failed!\n");
		return FALSE;
	}

//	//打印ae公钥，可删除-----begin------
//	pTmp = deraepubkey;
//	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
//	aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);
//	printf("ae's PublicKey is: \n");
//	for (i = 0; i < aepubkeyLen; i++)
//	{
//		printf("%02x", deraepubkey[i]);
//	}
//	printf("\n");
//	//打印ae公钥，可删除--------end-------

	//验证AE的签名
	if (verify_sign((BYTE *)recv_certificate_auth_requ_buffer, sizeof(certificate_auth_requ)-sizeof(sign_attribute),recv_certificate_auth_requ_buffer->aesign.sign.data,recv_certificate_auth_requ_buffer->aesign.sign.length,aepubKey))
	{
		printf("ASU验证AE签名正确......\n");
		EVP_PKEY_free(aepubKey);
	}
	else
		return FALSE;


	//填充wai_packet_head
	send_certificate_auth_resp_buffer->wai_packet_head.version = 1;
	send_certificate_auth_resp_buffer->wai_packet_head.type = 1;
	send_certificate_auth_resp_buffer->wai_packet_head.subtype = CERTIFICATE_AUTH_RESP;
	send_certificate_auth_resp_buffer->wai_packet_head.reserved = 0;
	send_certificate_auth_resp_buffer->wai_packet_head.length = sizeof(certificate_auth_resp);
	send_certificate_auth_resp_buffer->wai_packet_head.packetnumber = 4;
	send_certificate_auth_resp_buffer->wai_packet_head.fragmentnumber = 0;
	send_certificate_auth_resp_buffer->wai_packet_head.identify = 0;

	//填充ADDID
	bzero((send_certificate_auth_resp_buffer->addid.mac1),sizeof(send_certificate_auth_resp_buffer->addid.mac1));
	bzero((send_certificate_auth_resp_buffer->addid.mac2),sizeof(send_certificate_auth_resp_buffer->addid.mac2));

	//填充证书验证结果字段
	send_certificate_auth_resp_buffer->cervalidresult.type = 2; /* 证书验证结果属性类型 (2)*/
	send_certificate_auth_resp_buffer->cervalidresult.length = sizeof(certificate_valid_result);
	memcpy(send_certificate_auth_resp_buffer->cervalidresult.random1,recv_certificate_auth_requ_buffer->aechallenge,sizeof(recv_certificate_auth_requ_buffer->aechallenge));
	memcpy(send_certificate_auth_resp_buffer->cervalidresult.random2,recv_certificate_auth_requ_buffer->asuechallenge,sizeof(recv_certificate_auth_requ_buffer->asuechallenge));

	//ASU读取自己保存的证书文件夹中的ASUE证书，并与接收到的证书认证请求分组中的ASUE证书字段比对是否一致，若一致将证书认证请求分组中的ASUE证书字段复制到证书认证响应分组中的证书认证结果结构体中的相应字段
	memset(cert_buffer, 0, sizeof(cert_buffer));
	if (!getCertData(1, cert_buffer, &cert_len))    //先读取ASUE证书，"./newcerts/usercert1.pem"
	{
		printf("将ASUE证书保存到缓存buffer失败!");
		return FALSE;
	}

	asuecertcheck = strncmp((char *)cert_buffer,(char *)(recv_certificate_auth_requ_buffer->staasuecer.cer_X509),cert_len);
	if(asuecertcheck == 0)
	{
		memcpy(&(send_certificate_auth_resp_buffer->cervalidresult.certificate1),&(recv_certificate_auth_requ_buffer->staasuecer),sizeof(certificate));
	}


	//ASU读取自己保存的证书文件夹中的AE证书，并与接收到的证书认证请求分组中的AE证书字段比对是否一致，若一致将证书认证请求分组中的AE证书字段复制到证书认证响应分组中的证书认证结果结构体中的相应字段
	memset(cert_buffer, 0, sizeof(cert_buffer));
	if (!getCertData(2, cert_buffer, &cert_len))    //先读取AE证书，"./newcerts/usercert2.pem"
	{
		printf("将AE证书保存到缓存buffer失败!");
		return FALSE;
	}

	aecertcheck = strncmp((char *)cert_buffer,(char *)(recv_certificate_auth_requ_buffer->staaecer.cer_X509),cert_len);
	if(aecertcheck == 0)
	{
		memcpy(&(send_certificate_auth_resp_buffer->cervalidresult.certificate2),&(recv_certificate_auth_requ_buffer->staaecer),sizeof(certificate));
	}

	if((asuecertcheck == 0)&&(aecertcheck == 0))
	{
		//验证AE和ASUE的数字证书
		//X509_Cert_Verify(int aecertnum, int asuecertnum)
		//aecertnum = 2;asuecertnum = 1
		//今后需要根据recv_certificate_auth_requ_buffer->staasuecer.cer_identify字段值来提取证书文件的编号等信息
		CertVerifyResult = X509_Cert_Verify(2,1);
		//根据证书验证结果来设置send_certificate_auth_resp_buffer->cervalidresult.cerresult1和send_certificate_auth_resp_buffer->cervalidresult.cerresult2字段值
		//证书验证结果除了有效和无效大的分类外，还应有具体的说明，这一点有待细化修改！
		if (CertVerifyResult == AE_OK_ASUE_OK)
		{
			send_certificate_auth_resp_buffer->cervalidresult.cerresult1 = 0; //ASUE证书验证正确有效
			send_certificate_auth_resp_buffer->cervalidresult.cerresult2 = 0; //AE证书验证正确有效
		}
	}
	else
	{
		if ((asuecertcheck != 0)&&(aecertcheck == 0))
		{
			send_certificate_auth_resp_buffer->cervalidresult.cerresult1 = 1; //ASUE证书验证错误无效
			send_certificate_auth_resp_buffer->cervalidresult.cerresult2 = 0; //AE证书验证正确有效
		}
		else if ((asuecertcheck == 0)&&(aecertcheck != 0))
		{
			send_certificate_auth_resp_buffer->cervalidresult.cerresult1 = 0; //ASUE证书验证正确有效
			send_certificate_auth_resp_buffer->cervalidresult.cerresult2 = 1; //AE证书验证错误无效
		}
	}

	//ASU使用CA的私钥(cakey.pem)来生成对证书验证结果字段的签名和对整个证书认证响应分组(除本字段外)的签名
	privKey = getprivkeyfromprivkeyfile(0);         //0号密钥文件-CA(驻留在asu中)的密钥文件 "./private/cakey.pem"
	if (NULL == privKey)
	{
		printf("getprivkeyitsself().....failed!\n");
	}

	//ASU服务器对证书验证结果字段的签名
	if (!gen_sign((BYTE *)&(send_certificate_auth_resp_buffer->cervalidresult),sizeof(send_certificate_auth_resp_buffer->cervalidresult),cervalresasusign, &cervalresasusignlen, privKey))
	{
		printf("ASU服务器对证书验证结果字段的签名失败！");
	}
	send_certificate_auth_resp_buffer->cervalresasusign.sign.length = cervalresasusignlen;

	////////////////////////////////////////////////////////???
	printf("length=%d\n",send_certificate_auth_resp_buffer->cervalresasusign.sign.length);
		
	memcpy(send_certificate_auth_resp_buffer->cervalresasusign.sign.data, cervalresasusign, cervalresasusignlen);

	//ASU服务器对整个证书认证响应分组(除本字段外)的签名
	if (!gen_sign((BYTE *)send_certificate_auth_resp_buffer,send_certificate_auth_resp_buffer->wai_packet_head.length-sizeof(send_certificate_auth_resp_buffer->cerauthrespasusign),cerauthrespasusign, &cerauthrespasusignlen, privKey))
	{
		printf("ASU服务器对整个证书认证响应分组(除本字段外)的签名失败！");
	}
	send_certificate_auth_resp_buffer->cerauthrespasusign.sign.length = cerauthrespasusignlen;
	memcpy(send_certificate_auth_resp_buffer->cerauthrespasusign.sign.data, cerauthrespasusign, cerauthrespasusignlen);

	EVP_PKEY_free (privKey);

	//利用全局变量count来打印ASU中的fill_certificate_auth_resp_packet函数运行的次数，该部分打印如感觉没必要可删除
	printf("ASU中的fill_certificate_auth_resp_packet函数运行的次数为第%d次！\n",count);
	count++;

	return TRUE;

}


void process_request(int client_ae_socket, BYTE * recv_buffer,int recv_buffer_len)
{
//	certificate_auth_resp send_certificate_auth_resp_buffer;

//	certificate_auth_requ recv_certificate_auth_requ_buffer;
	
	EAP_certificate_auth_resp send_eap_certificate_auth_resp;  //New code
	EAP_certificate_auth_requ recv_eap_certificate_auth_requ;//New code


	BYTE subtype;
	BYTE send_buffer[15000];

	subtype = *(recv_buffer+sizeof(EAP_header)+3);     //WAI协议分组基本格式包头的第三个字节是分组的subtype字段，用来区分不同的分组
	memcpy(&recv_eap_certificate_auth_requ,recv_buffer,sizeof(recv_eap_certificate_auth_requ));//New code	

    switch(subtype)
    {
	case CERTIFICATE_AUTH_REQU:
		//bzero((BYTE *)&send_certificate_auth_resp_buffer,sizeof(send_certificate_auth_resp_buffer));
		//bzero((BYTE *)&recv_certificate_auth_requ_buffer,sizeof(recv_certificate_auth_requ_buffer));
		//memcpy(&recv_certificate_auth_requ_buffer,recv_buffer,sizeof(certificate_auth_requ));
		bzero((BYTE *)&send_eap_certificate_auth_resp,sizeof(send_eap_certificate_auth_resp));//New code
		
		send_eap_certificate_auth_resp.eap_header.code=2;//New code
		send_eap_certificate_auth_resp.eap_header.identifier=2;
		send_eap_certificate_auth_resp.eap_header.length=sizeof(send_eap_certificate_auth_resp);//New code
		send_eap_certificate_auth_resp.eap_header.type=192;//New code

		//if(!(fill_certificate_auth_resp_packet(&recv_certificate_auth_requ_buffer,&send_certificate_auth_resp_buffer)))
		//{
		//	printf("fill certificate auth resp packet failed!\n");
		//}

		if(!(fill_certificate_auth_resp_packet(&recv_eap_certificate_auth_requ.certificate_auth_requ_packet,&send_eap_certificate_auth_resp.certificate_auth_resp_packet)))//New code
		{
				printf("fill certificate auth resp packet failed!\n");
		}
		////////////////////////////////////////////////////////???
		printf("length=%d\n",send_eap_certificate_auth_resp.certificate_auth_resp_packet.cervalresasusign.sign.length);
		
		//memcpy(send_buffer,&send_certificate_auth_resp_buffer,sizeof(certificate_auth_resp));
		memcpy(send_buffer,&send_eap_certificate_auth_resp,sizeof(EAP_certificate_auth_resp));//New code
		break;
//	case XXX:其他case留作以后通信分组使用
//		XXX---其他case处理语句
//		break;
    }
    //send_to_peer(client_ae_socket, send_buffer, sizeof(certificate_auth_resp));
	send_to_peer(client_ae_socket, send_buffer, sizeof(EAP_certificate_auth_resp));
}



void * talk_to_ae(void * new_asu_server_socket_to_client_ae)
{
	int recv_buffer_len;
	int new_asu_server_socket = (int)new_asu_server_socket_to_client_ae;


	BYTE recv_buffer[15000];

	memset(recv_buffer, 0, sizeof(recv_buffer));

	printf("sizeof(certificate_auth_requ)=%d\n",sizeof(certificate_auth_requ));
	recv_buffer_len = recv_from_peer(new_asu_server_socket,recv_buffer,sizeof(EAP_certificate_auth_requ));
	
	//recv_buffer_len = recv(new_asu_server_socket, recv_buffer,sizeof(recv_buffer), 0);//MSG_WAITALL

	printf("\n-----------------\n");
/*

	printf("server receive %d data from client!!!!!!!\n",recv_buffer_len);

	if (recv_buffer_len == 9586)
	{
		printf("服务器接收到客户端%d字节的有效证书认证请求分组数据包\n", recv_buffer_len);
	}
*/
	printf("*******************\n");

	if (recv_buffer_len < 0)
	{
		printf("Server Recieve Data Failed!\n");
		close(new_asu_server_socket);
		pthread_exit(NULL);
	}
	if (recv_buffer_len == 0)
	{
		close(new_asu_server_socket);
		pthread_exit(NULL);
	}

	process_request(new_asu_server_socket, recv_buffer, recv_buffer_len);

	close(new_asu_server_socket);
	pthread_exit(NULL);


}


int main(int argc, char **argv)
{
	//BYTE * userID;
	OpenSSL_add_all_algorithms();

//	//main函数的第二个参数为演示第一部分所用，即为证书的用户名
//	if (argc != 2)
//	{
//		printf("程序运行输入参数有误！");
//		exit(1);
//	}
//	userID = argv[1];
//	init_user_table();

	//**************************************演示清单第一部分离线证书签发等操作 begin***************************************************
	//演示清单第一部分，由于2013.8.15演示的数字证书是离线生成并下载的，所以为了不耽误整体演示的时间(AE、ASUE的证书生成操作与CA证书【驻留在ASU中】类似，但是浪费时间)
	//该部分演示建议在单独的工程程序中演示，即整个ASU演示运行两个演示程序：ASU_A程序和ASU_B程序
	//ASU_A程序与ASU_B程序不同之处仅仅是ASU_A程序运行演示清单第一部分，ASU_B程序不运行演示清单第一部分,ASU_B程序所使用的所有数字证书(以及demoCA目录)都是提前生成好的。

//	CA_initial();
//	generate_keypair_and_certrequest(userID);
//	CA_sign_cert(userID);

	//**************************************演示清单第一部分离线证书签发等操作 end********************************************************


	//**************************************演示清单第二部分WAPI的WAI认证过程演示 begin***************************************************
	pthread_mutex_init(&user_table_mutex, NULL);
	int asu_server_socket = init_server_socket();

	pthread_t child_thread;
	pthread_attr_t child_thread_attr;
	pthread_attr_init(&child_thread_attr);
	pthread_attr_setdetachstate(&child_thread_attr, PTHREAD_CREATE_DETACHED);

	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);
		int new_asu_server_socket = accept(asu_server_socket,
				(struct sockaddr*) &client_addr, &length);
		if (new_asu_server_socket < 0)
		{
			printf("Server Accept Failed!\n");
			break;
		}
		if (pthread_create(&child_thread, &child_thread_attr, talk_to_ae,(void *) new_asu_server_socket) < 0)
			printf("pthread_create Failed : %s\n", strerror(errno));
	}
   //**************************************演示清单第二部分WAPI的WAI认证过程演示 end***************************************************
   return 0;
}
