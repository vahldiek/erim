/*
 * erim_processmappings.h
 *
 *  Based on https://github.com/ouadev/proc_maps_parser
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <erim_processmappings.h>

static void _pmparserSplitLine(
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
erim_procmaps* erim_pmapsParse(int pid) {
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

	erim_procmaps* list_maps = NULL;
	erim_procmaps* tmp = NULL;
	erim_procmaps* current_node = NULL;
	char addr1[20], addr2[20], perm[8], offset[20], dev[10], inode[30],
			pathname[600];

	while ((c = fgetc(file)) != EOF) {

		if(fgets(buf + 1, 259, file) == NULL) {
			return NULL;
		}

		buf[0] = c;

//		fprintf(stderr, "%s\n", buf);

		//allocate a node
		tmp = (erim_procmaps*) malloc(sizeof(erim_procmaps));

		//fill the node
		_pmparserSplitLine(buf, addr1, addr2, perm, offset, dev, inode,
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

erim_procmaps* erim_pmapsNext(erim_procmaps * cur) {
	return cur->next;
}

void erim_pmapsFree(erim_procmaps* maps_list) {
	if (maps_list == NULL )
		return;

	erim_procmaps* act = maps_list;
	erim_procmaps* nxt = act->next;
	while (act != NULL ) {
		free(act);
		act = nxt;
		if (nxt != NULL )
			nxt = nxt->next;
	}

}
