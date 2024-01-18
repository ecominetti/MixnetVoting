#include "APISimulator.h"

//  Windows
#ifdef _WIN32

#include <intrin.h>
uint64_t rdtscp(){
    return __rdtscp();
}

//  Linux/GCC
#else

uint64_t rdtscp(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtscp" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}



#endif

int main(int argc, char *arg[]) {
	FILE *resultadoCycles;
	unsigned long long onVoterActiveCycles, onChallengeCycles;
	uint64_t t0,t1,t;
  	int numTests=3;
	uint32_t vote;
	uint8_t infoContest=0x3f;
	int eleitoresHabilitados;

	printf("Benchmark do sistema de votacao E2Easy\n\n");

	resultadoCycles = fopen("BenchSim","a");
	if (resultadoCycles==NULL) {
		printf("Erro arquivo\n");
		return 0;
	}

	for (eleitoresHabilitados = 1; eleitoresHabilitados <= 5; eleitoresHabilitados+=1) {

		fprintf(resultadoCycles, "Numero eleitores = %d (%d votos), %d testes\n", eleitoresHabilitados, eleitoresHabilitados*6, numTests);
		fprintf(resultadoCycles, "    Setup;  onStart;onVoterActive;  onChallenge;    onFinish\n");
		fflush(resultadoCycles);
		printf("Eleitores = %d\n",eleitoresHabilitados);

		for (int bm = 0; bm < numTests; bm++) {

			if (bm%100==0) {
				printf("Test = %d\n",bm);
			}

			t0 = rdtscp();
			
			Setup();
			t1 = rdtscp(); t = t1-t0;
			fprintf(resultadoCycles, "%9lld;", t);

			t0 = rdtscp();
			
			onStart (infoContest);
			t1 = rdtscp(); t = t1-t0;
			fprintf(resultadoCycles, "%9lld;", t);

			onVoterActiveCycles = 0;
			onChallengeCycles = 0;
			
			for (int i = 0; i < eleitoresHabilitados; i++) {
				getrandom(&vote, sizeof(vote), 0);
				vote%=100000;
				if (vote < 10000){
					vote+=10000;
				}
				t0 = rdtscp();
				bench_before();
				onVoterActive(vote, 0);
				t1 = rdtscp(); t = t1-t0;
				onVoterActiveCycles+=t;

				getrandom(&vote, sizeof(vote), 0);
				vote%=10000;
				if (vote < 1000){
					vote+=1000;
				}
				t0 = rdtscp();
				bench_before();
				onVoterActive(vote, 1);
				t1 = rdtscp(); t = t1-t0;
				onVoterActiveCycles+=t;

				getrandom(&vote, sizeof(vote), 0);
				vote%=1000;
				if (vote < 100){
					vote+=100;
				}
				t0 = rdtscp();
				bench_before();
				onVoterActive(vote, 2);
				t1 = rdtscp(); t = t1-t0;
				onVoterActiveCycles+=t;

				getrandom(&vote, sizeof(vote), 0);
				vote%=1000;
				if (vote < 100){
					vote+=100;
				}
				t0 = rdtscp();
				bench_before();
				onVoterActive(vote, 3);
				t1 = rdtscp(); t = t1-t0;
				onVoterActiveCycles+=t;

				getrandom(&vote, sizeof(vote), 0);
				vote%=100;
				if (vote < 10){
					vote+=10;
				}
				t0 = rdtscp();
				bench_before();
				onVoterActive(vote, 4);
				t1 = rdtscp(); t = t1-t0;
				onVoterActiveCycles+=t;

				getrandom(&vote, sizeof(vote), 0);
				vote%=100;
				if (vote < 10){
					vote+=10;
				}
				t0 = rdtscp();
				bench_before();
				onVoterActive(vote, 5);
				t1 = rdtscp(); t = t1-t0;
				onVoterActiveCycles+=t;

				t0 = rdtscp();
				bench_before();
				onChallenge (1);
				t1 = rdtscp(); t = t1-t0;
				onChallengeCycles+=t;
			}

			fprintf(resultadoCycles, "%13lld;%13lld;", onVoterActiveCycles,onChallengeCycles);

			t0 = rdtscp();
			
			onFinish();
			t1 = rdtscp(); t = t1-t0;
			fprintf(resultadoCycles, "%12lld\n", t);
			fflush(resultadoCycles);
			system("bash CleanSession.sh");

		}
	}

	fclose (resultadoCycles);

  	return 0;
}