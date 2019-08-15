/*
 * eapi_processmappings.h
 *
 *  Created on: Sep 11, 2017
 *      Author: vahldiek
 *
 *  Based on https://github.com/ouadev/proc_maps_parser
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <eapi_processmappings.h>

static void _pmparser_split_line(
		char*buf,char*addr1,char*addr2,
		char*perm,char* offset,char* device,char*inode,
		char* pathname){
	//
	int orig=0;
	int i=0;
	//addr1
	while(buf[i]!='-'){
		addr1[i-orig]=buf[i];
		i++;
	}
	addr1[i]='\0';
	i++;
	//addr2
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		addr2[i-orig]=buf[i];
		i++;
	}
	addr2[i-orig]='\0';

	//perm
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		perm[i-orig]=buf[i];
		i++;
	}
	perm[i-orig]='\0';
	//offset
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		offset[i-orig]=buf[i];
		i++;
	}
	offset[i-orig]='\0';
	//dev
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		device[i-orig]=buf[i];
		i++;
	}
	device[i-orig]='\0';
	//inode
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' '){
		inode[i-orig]=buf[i];
		i++;
	}
	inode[i-orig]='\0';
	//pathname
	pathname[0]='\0';
	while(buf[i]=='\t' || buf[i]==' ')
		i++;
	orig=i;
	while(buf[i]!='\t' && buf[i]!=' ' && buf[i]!='\n'){
		pathname[i-orig]=buf[i];
		i++;
	}
	pathname[i-orig]='\0';

}

// pid = -1 -> /proc/self/maps
procmaps_t* eapi_pmaps_parse(int pid) {
	char maps_path[500];
	if (pid >= 0) {
		sprintf(maps_path, "/proc/%d/maps", pid);
	} else {
		sprintf(maps_path, "/proc/self/maps");
	}

	FILE* file = fopen(maps_path, "r");
	if (!file) {
		fprintf(stderr, "Couldn't open process map files\n");
		return NULL ;
	}

	int ind = 0;
	char buf[3000];
	char c;

	procmaps_t* list_maps = NULL;
	procmaps_t* tmp = NULL;
	procmaps_t* current_node = NULL;
	char addr1[20], addr2[20], perm[8], offset[20], dev[10], inode[30],
			pathname[600];

	while ((c = fgetc(file)) != EOF) {

		if(fgets(buf + 1, 259, file) == NULL) {
			return NULL;
		}

		buf[0] = c;

//		fprintf(stderr, "%s\n", buf);

		//allocate a node
		tmp = (procmaps_t*) malloc(sizeof(procmaps_t));

		//fill the node
		_pmparser_split_line(buf, addr1, addr2, perm, offset, dev, inode,
				pathname);

		sscanf(addr1, "%lx", (long unsigned *) &tmp->addr_start);
		sscanf(addr2, "%lx", (long unsigned *) &tmp->addr_end);

		//size
		tmp->length = (unsigned long) (tmp->addr_end - tmp->addr_start);

		//perm
		strcpy(tmp->perm, perm);
		tmp->is_r = (perm[0] == 'r');
		tmp->is_w = (perm[1] == 'w');
		tmp->is_x = (perm[2] == 'x');
		tmp->is_p = (perm[3] == 'p');

		//offset
		sscanf(offset, "%lx", &tmp->offset);

		//device
		strcpy(tmp->dev, dev);

		//inode
		tmp->inode = atoi(inode);

		//pathname
		strcpy(tmp->pathname, pathname);
		tmp->next = NULL;
		//attach the node
		if (ind == 0) {
			list_maps = tmp;
			list_maps->next = NULL;
			current_node = list_maps;
		}
		current_node->next = tmp;
		current_node = tmp;
		ind++;
	}

	return list_maps;
}

procmaps_t* eapi_pmaps_next(procmaps_t * cur) {
	return cur->next;
}

void eapi_pmaps_free(procmaps_t* maps_list) {
	if (maps_list == NULL )
		return;

	procmaps_t* act = maps_list;
	procmaps_t* nxt = act->next;
	while (act != NULL ) {
		free(act);
		act = nxt;
		if (nxt != NULL )
			nxt = nxt->next;
	}

}
