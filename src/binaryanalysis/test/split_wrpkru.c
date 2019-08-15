/*
 * split_wrpkru.c
 *
 *  Created on: May 30, 2017
 *      Author: vahldiek
 */

int main(int argc, char **argv) {

	asm ("add %eax, 0xfffffff \n\t add %ebp, %edi");
}
