/*
 * moverip_wrpkru.c
 *
 *  Created on: Aug 23, 2017
 *      Author: vahldiek
 */

int main(int argc, char **argv) {

	asm ("call *0xef010f(%rip)");
}
