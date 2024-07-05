#include "APISimulator.h"



typedef struct _VoteTable {
	ec_t a,b;
	uint8_t trackingCode[SHA256HashSize];
	uint32_t timer;
} VoteTable;

static int voteNumber;
ec_t pubSignKey;
static bn_t privSignKey;
bn_t QRCodeSign[2];
size_t tamSig;
static uint8_t H0[CONTESTS][SHA256HashSize];
static uint8_t Hcurrent[CONTESTS][SHA256HashSize];
static uint32_t RDV[CONTESTS][VOTERS];
static VoteTable vTable[CONTESTS][VOTERS];
static ec_t key;
static ec_t keyTable[32];
static bn_t curveMod;
static ec_t a[CONTESTS];
static ec_t b[CONTESTS];
static uint32_t m[CONTESTS];
static bn_t r[CONTESTS];
static time_t timer[CONTESTS];
static uint8_t trackingCode[CONTESTS][SHA256HashSize];
static uint8_t voteContestCasted;
static uint8_t numberContests;
uint8_t QRCodeTrackingCode[CONTESTS*(SHA256HashSize+sizeof(uint32_t))];
static int tamQRCodeTrackingCode;
uint8_t QRCodeSpoilTrackingCode[CONTESTS*SHA256HashSize];
uint8_t QRCodeSpoilNonce[CONTESTS*32]; // size of nonce for EC
uint32_t QRCodeSpoilVotes[CONTESTS];
int sizeQRCodeSpoil[3];

static void initializeVoteTable(VoteTable *vTable){
	ec_null(a);
	ec_null(b);
	ec_new(a);
	ec_new(b);
	for (int i = 0; i < SHA256HashSize; i++) {
		vTable->trackingCode[i]=0x00;
	}
	vTable->timer=0x00;
}

static void finalizeVoteTable(VoteTable *vTable){
	ec_free(a);
	ec_free(b);
	for (int i = 0; i < SHA256HashSize; i++) {
		vTable->trackingCode[i]=0x00;
	}
	vTable->timer=0x00;
}

/* Function to sort an array using insertion sort */
static void insertionSort(uint32_t arr[], int n) {
	int i, key, j;
	for (i = 1; i < n; i++) {
		key = arr[i];
		j = i - 1;

		/* Move elements of arr[0..i-1], that are greater than key,
		   to one position ahead of their current position */
		while (j >= 0 && arr[j] > key) {
			arr[j + 1] = arr[j];
			j = j - 1;
		}
		arr[j + 1] = key;
	}
}


static void lerArquivoVoteOutput (char voteOutputName[20], uint8_t HTail[SHA256HashSize], uint8_t HHead[SHA256HashSize], 
							uint8_t HTrackCode[VOTERS][SHA256HashSize], time_t vTime[VOTERS], ec_t a[VOTERS], ec_t b[VOTERS], int numVoters) {
	FILE *voteOutput;
	uint8_t buffer[64];


	for (int i = 0; i < numVoters; i++) {
		ec_null(a[i]);
		ec_null(b[i]);
		ec_new(a[i]);		
		ec_new(b[i]);
	}

	voteOutput = fopen(voteOutputName,"r");
	if (voteOutput != NULL) {
		fread(HTail,sizeof(uint8_t),SHA256HashSize,voteOutput);
		fread(HHead,sizeof(uint8_t),SHA256HashSize,voteOutput);
		for (int i = 0; i < numVoters; i++) {
			fread(HTrackCode[i],sizeof(uint8_t),SHA256HashSize,voteOutput);
			fread(&vTime[i],sizeof(uint32_t),1,voteOutput);
			fread(buffer,sizeof(uint8_t),64,voteOutput);
			a[i]->coord = 1;
			fp_read_bin(a[i]->x,buffer,32);
			fp_read_bin(a[i]->y,buffer+32,32);
			fp_read_str(a[i]->z,"1",1,16);
			fread(buffer,sizeof(uint8_t),64,voteOutput);
			b[i]->coord = 1;
			fp_read_bin(b[i]->x,buffer,32);
			fp_read_bin(b[i]->y,buffer+32,32);
			fp_read_str(b[i]->z,"1",1,16);
		}	
	}
	fclose(voteOutput);
}

static void lerArquivoRDV (char RDVOutputName[20], uint32_t _m[VOTERS], int numVoters) {
	FILE *RDVOutput;
	uint32_t vote;

	RDVOutput = fopen(RDVOutputName,"r");
	if (RDVOutput != NULL) {
		for (int i = 0; i < numVoters; i++) {
			if (fscanf(RDVOutput,"%u",&vote) != EOF) {
				_m[i]=vote;
			}
		}
	}
	fclose(RDVOutput);
}

// static void lerArquivoZKP (char ZKPOutputName[20], nmod_poly_t rho, nmod_poly_t beta,
// 					nmod_poly_t s[VOTERS], commit_t d[VOTERS],
// 					nmod_poly_t t[VOTERS][2], nmod_poly_t _t[VOTERS][2],
// 					nmod_poly_t u[VOTERS][2], nmod_poly_t y[VOTERS][WIDTH][2], 
// 					nmod_poly_t _y[VOTERS][WIDTH][2], int numVoters) {
// 	FILE *ZKPOutput;

// 	nmod_poly_init(rho, MODP);
// 	nmod_poly_init(beta, MODP);

// 	nmod_poly_fit_length(rho, DEGREE);
// 	nmod_poly_fit_length(beta, DEGREE);

// 	nmod_poly_zero(rho);
// 	nmod_poly_zero(beta);
	

// 	for (int i = 0; i < numVoters; i++) {
// 		nmod_poly_init(s[i], MODP);

// 		nmod_poly_fit_length(s[i],DEGREE);

// 		nmod_poly_zero(s[i]);

// 		for (int j = 0; j < 2; j++) {
// 			nmod_poly_init(d[i].c1[j], MODP);
// 			nmod_poly_init(d[i].c2[j], MODP);
// 			nmod_poly_init(t[i][j], MODP);
// 			nmod_poly_init(_t[i][j], MODP);
// 			nmod_poly_init(u[i][j], MODP);
// 			for (int w = 0; w < WIDTH; w++) {
// 				nmod_poly_init(y[i][w][j], MODP);
// 				nmod_poly_init(_y[i][w][j], MODP);
// 			}


// 			nmod_poly_fit_length(d[i].c1[j], DEGCRT);
// 			nmod_poly_fit_length(d[i].c2[j], DEGCRT);
// 			nmod_poly_fit_length(t[i][j], DEGCRT);
// 			nmod_poly_fit_length(_t[i][j], DEGCRT);
// 			nmod_poly_fit_length(u[i][j], DEGCRT);
// 			for (int w = 0; w < WIDTH; w++) {
// 				nmod_poly_fit_length(y[i][w][j], DEGCRT);
// 				nmod_poly_fit_length(_y[i][w][j], DEGCRT);
// 			}

// 			nmod_poly_zero(d[i].c1[j]);
// 			nmod_poly_zero(d[i].c2[j]);
// 			nmod_poly_zero(t[i][j]);
// 			nmod_poly_zero(_t[i][j]);
// 			nmod_poly_zero(u[i][j]);
// 			for (int w = 0; w < WIDTH; w++) {
// 				nmod_poly_zero(y[i][w][j]);
// 				nmod_poly_zero(_y[i][w][j]);
// 			}

// 		}
// 	}

// 	ZKPOutput = fopen(ZKPOutputName,"r");
// 	if (ZKPOutput != NULL) {
// 		rho->length = DEGREE;
// 		beta->length = DEGREE;

// 		for (int coeff = 0; coeff < DEGREE; coeff++) {
// 			fread(rho->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 			*(rho->coeffs+coeff)&=0xFFFFFFFF;
// 		}

// 		for (int coeff = 0; coeff < DEGREE; coeff++) {
// 			fread(beta->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 			*(beta->coeffs+coeff)&=0xFFFFFFFF;
// 		}

// 		s[0]->length = DEGREE;
// 		for (int coeff = 0; coeff < DEGREE; coeff++) {
// 			fread(s[0]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 			*(s[0]->coeffs+coeff)&=0xFFFFFFFF;
// 		}

// 		for (int i = 1; i < numVoters-1; i++) {
// 			s[i]->length = DEGREE;

// 			for (int coeff = 0; coeff < DEGREE; coeff++) {
// 			fread(s[i]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 			*(s[i]->coeffs+coeff)&=0xFFFFFFFF;
// 			}
// 		}

// 		for (int i = 0; i < numVoters; i++){
// 			for (int j = 0; j < 2; j++) {
// 				d[i].c1[j]->length = DEGCRT;
// 				d[i].c2[j]->length = DEGCRT;
// 				t[i][j]->length = DEGCRT;
// 				_t[i][j]->length = DEGCRT;
// 				u[i][j]->length = DEGCRT;

// 				for (int coeff = 0; coeff < DEGCRT; coeff++) {
// 					fread(d[i].c1[j]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 					*(d[i].c1[j]->coeffs+coeff)&=0xFFFFFFFF;
// 				}

// 				for (int coeff = 0; coeff < DEGCRT; coeff++) {
// 					fread(d[i].c2[j]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 					*(d[i].c2[j]->coeffs+coeff)&=0xFFFFFFFF;
// 				}

// 				for (int coeff = 0; coeff < DEGCRT; coeff++) {
// 					fread(t[i][j]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 					*(t[i][j]->coeffs+coeff)&=0xFFFFFFFF;
// 				}

// 				for (int coeff = 0; coeff < DEGCRT; coeff++) {
// 					fread(_t[i][j]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 					*(_t[i][j]->coeffs+coeff)&=0xFFFFFFFF;
// 				}

// 				for (int coeff = 0; coeff < DEGCRT; coeff++) {
// 					fread(u[i][j]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 					*(u[i][j]->coeffs+coeff)&=0xFFFFFFFF;
// 				}

// 				for (int w = 0; w < WIDTH; w++) {
// 					y[i][w][j]->length = DEGCRT;
// 					_y[i][w][j]->length = DEGCRT;

// 					for (int coeff = 0; coeff < DEGCRT; coeff++) {
// 						fread(y[i][w][j]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 						*(y[i][w][j]->coeffs+coeff)&=0xFFFFFFFF;
// 					}

// 					for (int coeff = 0; coeff < DEGCRT; coeff++) {
// 						fread(_y[i][w][j]->coeffs+coeff, sizeof(uint32_t), 1, ZKPOutput);
// 						*(_y[i][w][j]->coeffs+coeff)&=0xFFFFFFFF;
// 					}
// 				}
// 			}
// 		}
// 	}
// 	fclose(ZKPOutput);

// }



void Setup() {
	FILE *keyFile;
	uint8_t buffer[32];
	core_init();

	ec_param_set_any();

	ec_null(key);
	ec_new(key);

	system("vmni -prot -sid \"SessionID\" -name \"Election\" -nopart 1 -thres 1 -maxciph 600 stub.xml");
	system("vmni -party -name \"MixServer\" stub.xml privInfo.xml localProtInfo.xml");
	system("vmni -merge localProtInfo.xml protInfo.xml");
	system("vmn -keygen -s privInfo.xml protInfo.xml publicKey");
	// system("vmn -precomp -s -auxsid \"mix0\"  privInfo.xml protInfo.xml");
	// system("vmn -precomp -s -auxsid \"mix1\"  privInfo.xml protInfo.xml");
	// system("vmn -precomp -s -auxsid \"mix2\"  privInfo.xml protInfo.xml");
	// system("vmn -precomp -s -auxsid \"mix3\"  privInfo.xml protInfo.xml");
	// system("vmn -precomp -s -auxsid \"mix4\"  privInfo.xml protInfo.xml");
	// system("vmn -precomp -s -auxsid \"mix5\"  privInfo.xml protInfo.xml");

	keyFile = fopen("publicKey", "rb");
	if (keyFile != NULL) {
		key->coord = 1;

		fseek(keyFile,0x9A,SEEK_SET);
		fread(buffer,1,32,keyFile);
		fp_read_bin(key->x,buffer,32);
		// for (int i = 0; i < 32; i++) {
		// 	printf("%02x ",buffer[i]);
		// }
		// printf("\n");

		fseek(keyFile,0x6,SEEK_CUR);
		fread(buffer,1,32,keyFile);
		fp_read_bin(key->y,buffer,32);
		// for (int i = 0; i < 32; i++) {
		// 	printf("%02x ",buffer[i]);
		// }
		// printf("\n");

		fp_read_str(key->z,"1",1,16);

		fclose(keyFile);
	}
	else {
		printf("Error opening keyFile!\n");
	}


	// ec_print(key);

	for (int i = 0; i < 32; i++) {
		ec_null(keyTable[i]);
		ec_new(keyTable[i]);
	}
	ec_mul_pre(keyTable,key);

	bn_null(curveMod);
	bn_new(curveMod);
	bn_read_str(curveMod,NIST_P256_R,strlen(NIST_P256_R),16);
}

void onStart (uint8_t infoContest) {
	FILE *publicSignatureKey;
	uint8_t Q[] = "Teste\0";
	uint8_t buffer[32];
	SHA256Context sha;
	bn_t aux;
	uint8_t overlineQ[SHA256HashSize];

	numberContests = 0;
	bn_null(aux);
	bn_new(aux);
	bn_null(privSignKey);
	bn_new(privSignKey);
	ec_null(pubSignKey);
	ec_new(pubSignKey);


	/* Create Signature Key pair */
	cp_ecdsa_gen(privSignKey,pubSignKey);

	/*Hash overlineQ=Hash(A,Q,PublicSignKey)*/
	SHA256Reset(&sha);

	SHA256Input(&sha, Q, strlen((char *)Q));

	ec_get_x(aux,key);
	SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

	ec_get_y(aux,key);
	SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

	ec_get_x(aux,pubSignKey);
	SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

	ec_get_y(aux,pubSignKey);
	SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

	SHA256Result(&sha, overlineQ);

	/*TODO: Process infoContest*/
	numberContests = infoContest;
	

	/* Create H0 for each contest table */
	for (uint8_t i = 0; i < CONTESTS; i++)
	{
		SHA256Reset(&sha);

		SHA256Input(&sha, overlineQ, SHA256HashSize);

		SHA256Input(&sha, &i, 1);

		SHA256Result(&sha, H0[i]);
	}

	for (int j = 0; j < CONTESTS; j++) {
		for (int i  = 0; i < SHA256HashSize; i++) {
			Hcurrent[j][i]=H0[j][i];
		}
	}

	/* Initialize voting table and RDV*/
	for (int i  = 0; i < VOTERS; i++) {
		for (int j = 0; j < CONTESTS; j++) {
			initializeVoteTable(&vTable[j][i]);
			RDV[j][i]=0x00;
		}
	}
	bn_null(QRCodeSign[0]);
	bn_new(QRCodeSign[0]);
	bn_null(QRCodeSign[1]);
	bn_new(QRCodeSign[1]);

	/* Initialize number of voters as 0 */
	voteNumber = 0;

	/* Initialize vote timestamp as 0 */
	for (int i = 0; i < CONTESTS; i++) {
		timer[i] = 0x00;
	}

	/* Initialize if a vote was casted for a contest as 0 */
	voteContestCasted = 0;

	/*TODO: Output Sign public key and H0 */
	publicSignatureKey = fopen("publicSignatureKey","wb");
	if (publicSignatureKey != NULL) {
		ec_get_x(aux,pubSignKey);
		bn_write_bin(buffer,32,aux);
		fwrite(buffer,sizeof(uint8_t),32,publicSignatureKey);
		ec_get_y(aux,pubSignKey);
		bn_write_bin(buffer,32,aux);
		fwrite(buffer,sizeof(uint8_t),32,publicSignatureKey);
		fclose(publicSignatureKey);
	}


	bn_free(aux);
}

void onVoterActive(uint32_t vote, uint8_t cont) {
	SHA256Context sha;
	uint32_t timerInt;
	uint8_t tempVote[4];
	ec_t P;
	uint8_t buffer[64];
	bn_t aux;

	/* Check if the contest provided is within range and enabled*/
	if (((numberContests >> cont) & 1) != 1) {
		printf("Error: contest not enabled\n");
	}
	else {

		/* Initialize EC point strToPt that will map the vote to a point */
		ec_null(P);
		ec_new(P);
		

		/* Map the vote to a point and add to temp m[contests] variable */
		m[cont] = vote;
		tempVote[0]=vote&0xFF;
		tempVote[1]=(vote>>8)&0xFF;
		tempVote[2]=(vote>>16)&0xFF;
		tempVote[3]=(vote>>24)&0xFF;
		
		ec_map(P,tempVote,4);
		// ec_print(P);
		

		/* Draw r randomly and create the encryption */
		bn_null(r[cont]);
		bn_new(r[cont]);
		ec_null(a[cont]);
		ec_null(b[cont]);
		ec_new(a[cont]);
		ec_new(b[cont]);

		bn_rand_mod(r[cont],curveMod);
		// bn_read_str(r[cont],"5bcdc2ceb8343b866e1bf0a3884459d0d0fc9a07b24ba99385ab8589b19752b8",65,16);
		ec_mul_gen(a[cont],r[cont]);
		ec_mul_fix(b[cont],keyTable,r[cont]);
		ec_add(b[cont],b[cont],P);

		ec_norm(a[cont],a[cont]);
		ec_norm(b[cont],b[cont]);




		/* Set timer as current time */
		time(&timer[cont]);

		timerInt=(uint32_t)timer[cont];

		/* Parse the commitment to coeffs variable */
		bn_null(aux)
		bn_new(aux);
		
		/* Compute tracking code */
		SHA256Reset(&sha);

		SHA256Input(&sha, Hcurrent[cont], SHA256HashSize);

		SHA256Input(&sha, (const uint8_t*)&timerInt, 4);

		fp_write_bin(buffer,32,a[cont]->x);
		fp_write_bin(buffer+32,32,a[cont]->y);
		SHA256Input(&sha, buffer, 64);

		fp_write_bin(buffer,32,b[cont]->x);
		fp_write_bin(buffer+32,32,b[cont]->y);
		SHA256Input(&sha, buffer, 64);

		// ec_get_x(aux,a[cont]);
		// SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

		// ec_get_y(aux,a[cont]);
		// SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

		// ec_get_x(aux,b[cont]);
		// SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

		// ec_get_y(aux,b[cont]);
		// SHA256Input(&sha, (const uint8_t*)aux, bn_bits(aux)/8);

		SHA256Result(&sha, trackingCode[cont]);

		bn_free(aux);

		/* Inform that a vote was casted for this contest */
		voteContestCasted += (0x01 << cont);
	}
}

void onChallenge (bool cast) {
	uint8_t numberActiveContests=0;

	/* If vote is cast, store it on table */
	if (cast){
		for (uint8_t cont = 0; cont < CONTESTS; cont++) {
			if (((voteContestCasted >> cont) & 1) == 1) {
				ec_copy(vTable[cont][voteNumber].a,a[cont]);
				ec_copy(vTable[cont][voteNumber].b,b[cont]);
				vTable[cont][voteNumber].timer=(uint32_t)timer[cont];

				/* Also set Hcurrent as the tracking code */
				for (int i = 0; i < SHA256HashSize; i++) {
					vTable[cont][voteNumber].trackingCode[i]=trackingCode[cont][i];
					Hcurrent[cont][i]=trackingCode[cont][i];
				}
				/* Add vote to RDV and sort RDV */
				RDV[cont][voteNumber]=m[cont];
				insertionSort(RDV[cont],voteNumber+1);
			}
		}

		/* Increment vote number as a vote has been registered */
		voteNumber++;


		/* TODO: Sign tracking code and output*/
		cp_ecdsa_sig(QRCodeSign[0],QRCodeSign[1],QRCodeTrackingCode,tamQRCodeTrackingCode,0,privSignKey);
		

	} else {
		/* Benaloh Challenge: output  Hcurrent, r and vote. Discard everything*/

		/* Initilize QRCodeVectors*/
		for (int i = 0; i < CONTESTS*32; i++) {
			QRCodeSpoilNonce[i]=0x00;
		}
		for (int i = 0; i < CONTESTS; i++) {
			QRCodeSpoilVotes[i]=0x00;
		}
		for (int i = 0; i < CONTESTS*SHA256HashSize; i++) {
			QRCodeSpoilTrackingCode[i]=0x00;
		}

		for (uint8_t cont = 0; cont < CONTESTS; cont++) {
			if (((voteContestCasted >> cont) & 1) == 1) {
				bn_write_bin((QRCodeSpoilNonce + numberActiveContests*32),32,r[cont]);

				for (int i = 0; i < SHA256HashSize; i++) {
					QRCodeSpoilTrackingCode[numberActiveContests*SHA256HashSize+i] =
													Hcurrent[cont][i];
					trackingCode[cont][i]=0x00;
				}
				QRCodeSpoilVotes[numberActiveContests]=m[cont];
				numberActiveContests++;
			}
		}
		sizeQRCodeSpoil[0]=numberActiveContests*SHA256HashSize;
		sizeQRCodeSpoil[1]=numberActiveContests*32;
		sizeQRCodeSpoil[2]=numberActiveContests;
	}

	/* free encryption and clear message vote */
	for (uint8_t cont = 0; cont < CONTESTS; cont++) {
		m[cont] = 0;
		bn_zero(r[cont]);
		bn_free(r[cont]);
		ec_free(a[cont]);
		ec_free(b[cont]);
	}
	voteContestCasted = 0x00;

}

void onFinish () {
	FILE *voteOutput, *RDVOutput;
	SHA256Context sha, shaRDV;
	uint8_t closeSignal[] = "CLOSE\0";
	uint8_t HashToSign[SHA256HashSize];
	uint8_t Phex[32];
	uint8_t buffer;
	uint8_t voteNumberBytes[4];
	// uint8_t dummy1[21] = {0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x02,0x01,0x00,0x00,0x00,0x21,0x00};
	// uint8_t dummy2[6] = {0x01,0x00,0x00,0x00,0x21,0x00};
	// uint8_t dummy3[16] = {0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x02,0x01,0x00,0x00,0x00,0x21,0x00};
	bn_t Signature[2];
	bn_t aux;
	char outputFileName[20], RDVFileName[20], aggrCiphertexts[20],verificatumCmd[100];

	bn_null(Signature[0]);
	bn_new(Signature[0]);
	bn_null(Signature[1]);
	bn_new(Signature[1]);
	bn_null(aux);
	bn_new(aux);

	voteNumberBytes[3] = voteNumber & 0xFF;
	voteNumberBytes[2] = (voteNumber>>8) & 0xFF;
	voteNumberBytes[1] = (voteNumber>>16) & 0xFF;
	voteNumberBytes[0] = (voteNumber>>24) & 0xFF; 


	for (uint8_t cont = 0; cont < CONTESTS; cont++) {
		if (((numberContests >> cont) & 1) == 1) {
			
			/* Compute Hlast */
			SHA256Reset(&sha);

			SHA256Input(&sha, Hcurrent[cont], SHA256HashSize);

			SHA256Input(&sha, (const uint8_t*)closeSignal, strlen((char *)closeSignal));

			SHA256Result(&sha, Hcurrent[cont]);

			/* Parse vTable variables to Verificatum */
			snprintf(aggrCiphertexts,20,"ciphertexts_%d", cont);
			voteOutput = fopen(aggrCiphertexts,"wb");
			if (voteOutput != NULL) {
				buffer=0;
				fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
				fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
				fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
				fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
				buffer=2;
				fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
				buffer=0;
				fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
				fwrite(voteNumberBytes,sizeof(uint8_t),4,voteOutput);
				for (int i = 0; i < voteNumber; i++) {
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=2;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=1;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0x21;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					ec_get_x(aux, vTable[cont][i].a);
					bn_write_bin(Phex,32,aux);
					fwrite(Phex,sizeof(uint8_t),32,voteOutput);
					buffer=1;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0x21;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					ec_get_y(aux, vTable[cont][i].a);
					bn_write_bin(Phex,32,aux);
					fwrite(Phex,sizeof(uint8_t),32,voteOutput);
				}
				buffer=0;
				fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
				fwrite(voteNumberBytes,sizeof(uint8_t),4,voteOutput);
				for (int i = 0; i < voteNumber; i++) {
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=2;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=1;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0x21;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					ec_get_x(aux, vTable[cont][i].b);
					bn_write_bin(Phex,32,aux);
					fwrite(Phex,sizeof(uint8_t),32,voteOutput);
					buffer=1;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0x21;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					buffer=0;
					fwrite(&buffer,sizeof(uint8_t),1,voteOutput);
					ec_get_y(aux, vTable[cont][i].b);
					bn_write_bin(Phex,32,aux);
					fwrite(Phex,sizeof(uint8_t),32,voteOutput);
				}
				fclose(voteOutput);
				snprintf(verificatumCmd,100,"vmn -mix -auxsid \"mix%d\" -s privInfo.xml protInfo.xml %s plaintexts_%d", cont, aggrCiphertexts,cont);
				system(verificatumCmd);
			} else {
				printf("Error in creating ciphertexts list\n");
			}
 
			
			SHA256Reset(&sha);
			SHA256Reset(&shaRDV);

			snprintf(outputFileName,20,"voteOutput_Cont%d", cont);
			snprintf(RDVFileName,20,"RDVOutput_Cont%d", cont);

			voteOutput = fopen(outputFileName, "w");
			RDVOutput = fopen(RDVFileName, "w");

			fwrite(H0[cont], sizeof(uint8_t), SHA256HashSize,voteOutput);
			SHA256Input(&sha, H0[cont], SHA256HashSize);

			fwrite(Hcurrent[cont], sizeof(uint8_t), SHA256HashSize,voteOutput);
			SHA256Input(&sha, Hcurrent[cont], SHA256HashSize);

			for (int i = 0; i < voteNumber; i++) {
				fprintf(RDVOutput, "%u",RDV[cont][i]);
				SHA256Input(&shaRDV, (const uint8_t*)&RDV[cont][i], 4);
				fprintf(RDVOutput, "\n");
				SHA256Input(&shaRDV, (const uint8_t*)"\n", 2);
					
				fwrite(vTable[cont][i].trackingCode, sizeof(uint8_t), SHA256HashSize,voteOutput);
				SHA256Input(&sha, vTable[cont][i].trackingCode, SHA256HashSize);
				fwrite(&vTable[cont][i].timer, sizeof(uint32_t), 1,voteOutput);
				SHA256Input(&sha, (const uint8_t*)&vTable[cont][i].timer, 4);

				ec_get_x(aux,vTable[cont][i].a);
				bn_write_bin(Phex,32,aux);
				fwrite(Phex, sizeof(uint8_t), 32,voteOutput);
				SHA256Input(&sha, (const uint8_t*)Phex, 32);

				ec_get_y(aux,vTable[cont][i].a);
				bn_write_bin(Phex,32,aux);
				fwrite(Phex, sizeof(uint8_t), 32,voteOutput);
				SHA256Input(&sha, (const uint8_t*)Phex, 32);

				ec_get_x(aux,vTable[cont][i].b);
				bn_write_bin(Phex,32,aux);
				fwrite(Phex, sizeof(uint8_t), 32,voteOutput);
				SHA256Input(&sha, (const uint8_t*)Phex, 32);

				ec_get_y(aux,vTable[cont][i].b);
				bn_write_bin(Phex,32,aux);
				fwrite(Phex, sizeof(uint8_t), 32,voteOutput);
				SHA256Input(&sha, (const uint8_t*)Phex, 32);
			}
			fclose(voteOutput);
			fclose(RDVOutput);

			/* Sign both files (from each hashed entry included)*/

			snprintf(outputFileName,20,"voteOutputSig_Cont%d", cont);
			snprintf(RDVFileName,20,"RDVOutputSig_Cont%d", cont);

			voteOutput = fopen(outputFileName, "w");
			RDVOutput = fopen(RDVFileName, "w");				

			SHA256Result(&sha, HashToSign);
			cp_ecdsa_sig(Signature[0],Signature[1],HashToSign,32,1,privSignKey);
			bn_write_bin(Phex,32,Signature[0]);
			fwrite(Phex, sizeof(uint8_t), 32,voteOutput);
			bn_write_bin(Phex,32,Signature[1]);
			fwrite(Phex, sizeof(uint8_t), 32,voteOutput);

			SHA256Result(&shaRDV, HashToSign);
			cp_ecdsa_sig(Signature[0],Signature[1],HashToSign,32,1,privSignKey);
			bn_write_bin(Phex,32,Signature[0]);
			fwrite(Phex, sizeof(uint8_t), 32,RDVOutput);
			bn_write_bin(Phex,32,Signature[1]);
			fwrite(Phex, sizeof(uint8_t), 32,RDVOutput);

			fclose(voteOutput);
			fclose(RDVOutput);
		}
	}

	for (int cont = 0; cont < CONTESTS; cont++) {
		for (int i = 0; i < VOTERS; i++) {
			finalizeVoteTable(&vTable[cont][i]);
		}
	}

	bn_free(Signature[0]);
	bn_free(Signature[1]);
	bn_free(aux);
	bn_zero(privSignKey);
	bn_free(privSignKey);
	ec_free(pubSignKey);
	ec_free(key);
	for (int i = 0; i < 32; i++) {
		ec_free(keyTable[i]);
	}
	bn_free(curveMod);

	core_clean();

	// commit_keyfree(&key);
	// commit_finish();
	// flint_randclear(rand);
	// flint_cleanup();
}

int createQRTrackingCode() {
	uint8_t numberActiveContests = 0;

	for (uint8_t cont = 0; cont < CONTESTS; cont++) {
			if (((numberContests >> cont) & 1) == 1) {
				for (int i = 0; i < SHA256HashSize; i++) {
					QRCodeTrackingCode[numberActiveContests*(SHA256HashSize+sizeof(uint32_t))+i] =
								trackingCode[cont][i];
				}
				for (int j = 0; j < 4; j++){
					QRCodeTrackingCode[SHA256HashSize+numberActiveContests*(SHA256HashSize+sizeof(uint32_t))+j] = 
								(timer[cont]>>(j*8))&0xFF;
				}
				numberActiveContests++;
			}
	}
	tamQRCodeTrackingCode = numberActiveContests*(SHA256HashSize+sizeof(uint32_t));
	return numberActiveContests*(SHA256HashSize+sizeof(uint32_t));
}



void verifyVote (uint8_t *QRTrack, uint8_t *QRSpoilTrack, uint8_t *QRSpoilNon, uint32_t *QRSpoilVot) {
	SHA256Context sha;
	ec_t _a[CONTESTS];
	ec_t _b[CONTESTS];
	ec_t P;
	bn_t _r[CONTESTS];
	uint8_t tempVote[4];
	uint8_t buffer[64];
	uint32_t timerInt[CONTESTS];
	uint8_t newTrCode[CONTESTS][SHA256HashSize];
	int index;
	int verified=TRUE;

	uint8_t QRTrackingCode[CONTESTS*(SHA256HashSize+sizeof(uint32_t))];
	uint8_t QRSpoilTrackingCode[CONTESTS*SHA256HashSize];
	uint8_t QRSpoilNonce[CONTESTS*32]; // Degree*2/8
	uint32_t QRSpoilVotes[CONTESTS];
	uint8_t numberActiveContests=0;

	/* Initialize internal vectors with external vectors*/
	for (uint8_t cont = 0; cont < CONTESTS; cont++) {
			if (((numberContests >> cont) & 1) == 1) {
				numberActiveContests++;
			}
	}
	memmove(QRTrackingCode,QRTrack,numberActiveContests*(SHA256HashSize+sizeof(uint32_t)));
	memmove(QRSpoilTrackingCode,QRSpoilTrack,numberActiveContests*SHA256HashSize);
	memmove(QRSpoilNonce, QRSpoilNon, numberActiveContests*32);
	memmove(QRSpoilVotes, QRSpoilVot, numberActiveContests*4);

	ec_null(P);
	ec_new(P);

	for (uint8_t cont = 0; cont < numberActiveContests; cont++) {
		ec_null(_a[cont]);
		ec_new(_a[cont]);
		ec_null(_b[cont]);
		ec_new(_b[cont]);
		bn_null(_r[cont]);
		bn_new(_r[cont]);
		
		tempVote[0]=QRSpoilVotes[cont]&0xFF;
		tempVote[1]=(QRSpoilVotes[cont]>>8)&0xFF;
		tempVote[2]=(QRSpoilVotes[cont]>>16)&0xFF;
		tempVote[3]=(QRSpoilVotes[cont]>>24)&0xFF;

		ec_map(P,tempVote,4);
		bn_read_bin(_r[cont],(QRCodeSpoilNonce + cont*32),32);
		
		ec_mul_gen(_a[cont],_r[cont]);
		ec_mul_fix(_b[cont],keyTable,_r[cont]);
		ec_add(_b[cont],_b[cont],P);

		ec_norm(_a[cont],_a[cont]);
		ec_norm(_b[cont],_b[cont]);

		timerInt[cont] = QRTrackingCode[SHA256HashSize+cont*(SHA256HashSize+sizeof(uint32_t))] |
					QRTrackingCode[SHA256HashSize+cont*(SHA256HashSize+sizeof(uint32_t))+1]<<8 |
						QRTrackingCode[SHA256HashSize+cont*(SHA256HashSize+sizeof(uint32_t))+2]<<16 |
							QRTrackingCode[SHA256HashSize+cont*(SHA256HashSize+sizeof(uint32_t))+3]<<24;


		/* Compute tracking code */
		SHA256Reset(&sha);

		SHA256Input(&sha, &QRSpoilTrackingCode[cont*SHA256HashSize], SHA256HashSize);

		SHA256Input(&sha, (const uint8_t*)&timerInt[cont], 4);

		fp_write_bin(buffer,32,_a[cont]->x);
		fp_write_bin(buffer+32,32,_a[cont]->y);
		SHA256Input(&sha, buffer, 64);

		fp_write_bin(buffer,32,_b[cont]->x);
		fp_write_bin(buffer+32,32,_b[cont]->y);
		SHA256Input(&sha, buffer, 64);

		SHA256Result(&sha, newTrCode[cont]);

		for (int z = 0; z < SHA256HashSize; z++){
			if(newTrCode[cont][z]!=QRTrackingCode[cont*(SHA256HashSize+sizeof(uint32_t))+z]) {
				verified=FALSE;
			}
		}
	}
	if (verified==TRUE){
		printf("\033[32m(SUCESSO) Tracking Code corresponde aos votos\033[0m\n");
	} else {
		printf("\033[31m(ERRO) Tracking Code nao corresponde aos votos\033[0m\n");
	}

	for (uint8_t cont = 0; cont < numberActiveContests; cont++) {
		bn_zero(_r[cont]);
		bn_free(_r[cont]);
		ec_free(_a[cont]);
		ec_free(_b[cont]);
	}
	ec_free(P);
	
}

void validateRDV (char RDVOutputName[20], char RDVSigOutputName[20], int numVoters){
	FILE *SigFile;
	SHA256Context sha;
	uint8_t hash[SHA256HashSize];
	uint8_t buffer[64];
	uint32_t _m[VOTERS];
	ec_t publicKey;
	bn_t Signature[2];
	int Success = -1;

	core_init();
	ec_param_set_any();

	ec_null(publicKey);
	ec_new(publicKey);

	bn_null(Signature[0]);
	bn_new(Signature[0]);
	bn_null(Signature[1]);
	bn_new(Signature[1]);

	SigFile = fopen("publicSignatureKey", "r");
	if(SigFile != NULL){
		fread(buffer, sizeof(uint8_t), 64, SigFile);
		fclose(SigFile);
	}
	fp_read_bin(publicKey->x,buffer,32);
	fp_read_bin(publicKey->y,buffer+32,32);
	fp_read_str(publicKey->z,"1",1,16);

	// printf("\nPublic Key: ");
	// ec_print(publicKey);
	// printf("\n");

	

	SHA256Reset(&sha);
	lerArquivoRDV(RDVOutputName,_m,numVoters);
	for (int i = 0; i < numVoters; i++) {
		SHA256Input(&sha, (const uint8_t*)&_m[i], 4);
		SHA256Input(&sha, (const uint8_t*)"\n", 2);
	}
	SHA256Result(&sha, hash);

	SigFile = fopen(RDVSigOutputName, "r");
	if(SigFile != NULL){
		fread(buffer, sizeof(uint8_t), 64, SigFile);
		fclose(SigFile);
	}
	bn_read_bin(Signature[0],buffer,32);
	bn_read_bin(Signature[1],buffer+32,32);

	Success = cp_ecdsa_ver(Signature[0], Signature[1], hash, 32, 1, publicKey);

	if (Success == 1){
		printf("\n\033[32mASSINATURA DO ARQUIVO RDV VERIFICADA COM SUCESSO!\033[0m\n");
	} else {
		printf("\n\n\033[31mERRO! -- ASSINATURA DO ARQUIVO RDV NAO VERIFICADA -- ERRO!\033[0m\n\n");
	}

	ec_free(publicKey);
	bn_free(Signature[0]);
	bn_free(Signature[1]);
	core_clean();
}

void validateVoteOutput (char voteOutputName[20], char voteSigOutputName[20], int numVoters){
	FILE *SigFile;
	SHA256Context sha;
	uint8_t hash[SHA256HashSize];
	ec_t publicKey;
	bn_t Signature[2];
	uint8_t buffer[64];
	ec_t a[VOTERS];
	ec_t b[VOTERS];
	uint8_t HTail[SHA256HashSize];
	uint8_t HHead[SHA256HashSize];
	uint8_t HTrackCode[VOTERS][SHA256HashSize];
	time_t vTime[VOTERS];
	int Success = -1;
	int result=1;
	uint8_t HCurrent[SHA256HashSize];
	uint8_t HNext[SHA256HashSize];
	uint8_t closeSignal[] = "CLOSE\0";

	core_init();
	ec_param_set_any();

	ec_null(publicKey);
	ec_new(publicKey);

	// for (int i = 0; i < VOTERS; i++) {
	// 	ec_null(a[i]);
	// 	ec_null(b[i]);
	// 	ec_new(a[i]);		
	// 	ec_new(b[i]);
	// }

	bn_null(Signature[0]);
	bn_new(Signature[0]);
	bn_null(Signature[1]);
	bn_new(Signature[1]);

	SigFile = fopen("publicSignatureKey", "r");
	if(SigFile != NULL){
		fread(buffer, sizeof(uint8_t), 64, SigFile);
		fclose(SigFile);
	}
	fp_read_bin(publicKey->x,buffer,32);
	fp_read_bin(publicKey->y,buffer+32,32);
	fp_read_str(publicKey->z,"1",1,16);

	// printf("\nPublic Key: ");
	// ec_print(publicKey);
	// printf("\n");

	SHA256Reset(&sha);

	lerArquivoVoteOutput(voteOutputName, HTail, HHead, HTrackCode, vTime, a, b, numVoters);

	SHA256Input(&sha, HTail, SHA256HashSize);
	// for (int j = 0; j <)
	SHA256Input(&sha, HHead, SHA256HashSize);

	for (int i = 0; i < numVoters; i++) {
		SHA256Input(&sha, HTrackCode[i], SHA256HashSize);
		SHA256Input(&sha, (const uint8_t*)&vTime[i], 4);
		fp_write_bin(buffer,32,a[i]->x);
		fp_write_bin(buffer+32,32,a[i]->y);
		SHA256Input(&sha, buffer, 64);
		fp_write_bin(buffer,32,b[i]->x);
		fp_write_bin(buffer+32,32,b[i]->y);
		SHA256Input(&sha, buffer, 64);
	}
	SHA256Result(&sha, hash);

	SigFile = fopen(voteSigOutputName, "r");
	if(SigFile != NULL){
		fread(buffer, sizeof(uint8_t), 64, SigFile);
		fclose(SigFile);
	}
	bn_read_bin(Signature[0],buffer,32);
	bn_read_bin(Signature[1],buffer+32,32);

	Success = cp_ecdsa_ver(Signature[0], Signature[1], hash, 32, 1, publicKey);

	
	if (Success == 1){
		printf("\n\033[32mASSINATURA DO ARQUIVO DE CIFRAS VERIFICADA COM SUCESSO!\033[0m\n");
	} else {
		printf("\n\n\033[31mERRO! -- ASSINATURA DO ARQUIVO DE CIFRAS NAO VERIFICADA -- ERRO!\033[0m\n\n");
	}

	/* Check Commitment Chain*/

	for (int j = 0; j < SHA256HashSize; j++){
		HCurrent[j]=HTail[j];
		// printf("%02x ",HCurrent[j]);
	}
	// printf("\n\n");

	for(int i = 0; i < numVoters; i++){

		/* Compute next tracking code */
		SHA256Reset(&sha);

		SHA256Input(&sha, HCurrent, SHA256HashSize);

		SHA256Input(&sha, (const uint8_t*)&vTime[i], 4);

		fp_write_bin(buffer,32,a[i]->x);
		fp_write_bin(buffer+32,32,a[i]->y);
		SHA256Input(&sha, buffer, 64);

		fp_write_bin(buffer,32,b[i]->x);
		fp_write_bin(buffer+32,32,b[i]->y);
		SHA256Input(&sha, buffer, 64);

		SHA256Result(&sha, HNext);

		for (int j = 0; j < SHA256HashSize; j++){
			if(HNext[j]!=HTrackCode[i][j]){
				result = 0;
			}
		}

		for (int j = 0; j < SHA256HashSize; j++){
			HCurrent[j]=HNext[j];
			// printf("%02x ",HCurrent[j]);
		}
	// printf("\n\n");

	}
	/* Compute HHead */
	SHA256Reset(&sha);

	SHA256Input(&sha, HCurrent, SHA256HashSize);

	SHA256Input(&sha, (const uint8_t*)closeSignal, strlen((char *)closeSignal));

	SHA256Result(&sha, HNext);

	for (int j = 0; j < SHA256HashSize; j++){
		if(HNext[j]!=HHead[j]){
			result = 0;
		}
	}

	if(result == 1) {
		printf("\n\033[32mHASH CHAIN DAS CIFRAS VERIFICADA COM SUCESSO!\033[0m\n");
	} else {
		printf("\n\n\033[31mERRO! -- HASH CHAIN DAS CIFRAS NAO VERIFICADA -- ERRO!\033[0m\n\n");
	}

	ec_free(publicKey);
	for (int i = 0; i < numVoters; i++) {
		ec_free(a[i]);
		ec_free(b[i]);
	}
	bn_free(Signature[0]);
	bn_free(Signature[1]);
	core_clean();
}


// void validateZKPOutput (char ZKPOutputName[20], char ZKPSigOutputName[20], 
// 						char RDVOutputName[20],	char voteOutputName[20], 
// 						int numVoters) {
// 	nmod_poly_t rho, beta;
// 	nmod_poly_t s[VOTERS];
// 	commit_t d[VOTERS];
// 	nmod_poly_t t[VOTERS][2], _t[VOTERS][2];
// 	nmod_poly_t u[VOTERS][2];
// 	nmod_poly_t y[VOTERS][WIDTH][2], _y[VOTERS][WIDTH][2];
// 	nmod_poly_t t0;
// 	uint8_t HTail[SHA512HashSize];
// 	uint8_t HHead[SHA512HashSize];
// 	uint8_t HTrackCode[VOTERS][SHA512HashSize];
// 	time_t vTime[VOTERS];
// 	commit_t com[VOTERS];
// 	nmod_poly_t _m[VOTERS];
// 	int flag, result = 1;
// 	flint_rand_t rand;
// 	commitkey_t keyTemp;
// 	FILE *SigFile;
// 	SHA512Context sha;
// 	uint8_t hash[SHA512HashSize];
// 	uint8_t Signature[pqcrystals_dilithium2_BYTES];
// 	int Success = -1;

// 	flint_randinit(rand);
//     commit_setup();

// 	commit_keygen(&keyTemp, rand);
	
// 	nmod_poly_init(t0, MODP);

// 	lerArquivoRDV(RDVOutputName,_m,numVoters);
// 	lerArquivoVoteOutput(voteOutputName, HTail, HHead, HTrackCode, vTime, com, numVoters);
// 	lerArquivoZKP (ZKPOutputName, rho, beta,
// 				   s, d, t, _t,
// 				   u, y, _y, numVoters);

// 	/* Normalise polys to avoid leading zeros */
// 	_nmod_poly_normalise(rho);
// 	_nmod_poly_normalise(beta);
// 	for (int i = 0; i < numVoters; i++) {
// 		_nmod_poly_normalise(s[i]);
// 		for (int j = 0; j < 2; j++) {
// 			_nmod_poly_normalise(d[i].c1[j]);
// 			_nmod_poly_normalise(d[i].c2[j]);
// 			_nmod_poly_normalise(com[i].c1[j]);
// 			_nmod_poly_normalise(com[i].c2[j]);
// 			_nmod_poly_normalise(t[i][j]);
// 			_nmod_poly_normalise(_t[i][j]);
// 			_nmod_poly_normalise(u[i][j]);
// 			for (int w = 0; w < WIDTH; w++){
// 				_nmod_poly_normalise(y[i][w][j]);
// 				_nmod_poly_normalise(_y[i][w][j]);
// 			}
// 		}
// 	}

// 	SHA512Reset(&sha);

// 	HashMp_ptr(&sha,rho->coeffs, sizeof(uint32_t), rho->length);
// 	HashMp_ptr(&sha,beta->coeffs, sizeof(uint32_t), beta->length);

// 	HashMp_ptr(&sha,s[0]->coeffs, sizeof(uint32_t), s[0]->length);

// 	for (int i = 1; i < numVoters-1; i++) {
// 		HashMp_ptr(&sha,s[i]->coeffs, sizeof(uint32_t), s[i]->length);
// 	}


// 	for (int l = 0; l < numVoters; l++) {
// 		for (int i = 0; i < 2; i++) {
// 			HashMp_ptr(&sha,d[l].c1[i]->coeffs, sizeof(uint32_t), d[0].c1[i]->length);
// 			HashMp_ptr(&sha,d[l].c2[i]->coeffs, sizeof(uint32_t), d[0].c2[i]->length);
// 			HashMp_ptr(&sha,t[l][i]->coeffs, sizeof(uint32_t), t[l][i]->length);
// 			HashMp_ptr(&sha,_t[l][i]->coeffs, sizeof(uint32_t), _t[l][i]->length);
// 			HashMp_ptr(&sha,u[l][i]->coeffs, sizeof(uint32_t), u[l][i]->length);

// 			for (int j = 0; j < WIDTH; j++) {
// 				HashMp_ptr(&sha,y[l][j][i]->coeffs, sizeof(uint32_t), y[l][j][i]->length);
// 				HashMp_ptr(&sha,_y[l][j][i]->coeffs, sizeof(uint32_t), _y[l][j][i]->length);
// 			}
// 		}
// 	}

// 	SHA512Result(&sha, hash);

// 	SigFile = fopen(ZKPSigOutputName, "r");
// 	if(SigFile != NULL){
// 		fread(Signature, sizeof(uint8_t), pqcrystals_dilithium2_BYTES, SigFile);
// 	}
// 	fclose(SigFile);

// 	Success = pqcrystals_dilithium2aes_ref_verify(Signature, pqcrystals_dilithium2_BYTES,
//                                         		 hash, SHA512HashSize,
//                                         		 pubSignKey);

// 	if (Success == 0){
// 		printf("\n\033[32mASSINATURA DO ARQUIVO DE ZKP VERIFICADA COM SUCESSO!\033[0m\n");
// 	} else {
// 		printf("\n\n\033[31mERRO! -- ASSINATURA DO ARQUIVO DE ZKP NAO VERIFICADA -- ERRO!\033[0m\n\n");
// 	}

// 	/* Prover shifts the messages by rho */
// 	for (int i = 0; i < numVoters; i++) {
// 		nmod_poly_sub(_m[i], _m[i], rho);
// 	}

// 	/* Verifier shifts the commitment by rho. */
// 	for (int i = 0; i < numVoters; i++) {
// 		for (int j = 0; j < 2; j++) {
// 			nmod_poly_rem(t0, rho, *commit_irred(j));
// 			nmod_poly_sub(com[i].c2[j], com[i].c2[j], t0);
// 		}
// 	}

// 	result = shuffle_verifier(y, _y, t, _t, u, d, s, com, _m, rho, &keyTemp, numVoters);

// 	if (result == 1) {
// 		printf("\n\033[32mPROVA ZKP DE SHUFFLE VERIFICADA COM SUCESSO!\033[0m\n");
// 	} else {
// 		printf("\n\n\033[31mERRO! -- PROVA ZKP DE SHUFFLE NAO VERIFICADA -- ERRO!\033[0m\n\n");
// 	}

// 	nmod_poly_clear(t0);
// 	nmod_poly_clear(rho);
// 	nmod_poly_clear(beta);
// 	for(int i = 0; i < numVoters; i++) {
// 		commit_free(&com[i]);
// 		commit_free(&d[i]);
// 		nmod_poly_clear(_m[i]);
// 		nmod_poly_clear(s[i]);
// 		for (int j = 0; j < 2; j++){
// 			nmod_poly_clear(t[i][j]);
// 			nmod_poly_clear(_t[i][j]);
// 			nmod_poly_clear(u[i][j]);
// 			for (int w = 0; w < WIDTH; w++){
// 				nmod_poly_clear(y[i][w][j]);
// 				nmod_poly_clear(_y[i][w][j]);
// 			}
// 		}
// 	}
// 	commit_keyfree(&keyTemp);
// 	commit_finish();
// 	flint_randclear(rand);
// 	flint_cleanup();

// }

int numberTotalvoters() {
	return voteNumber;
}
