/**
 * Less Simple, Yet Stupid Filesystem.
 * 
 * Mohammed Q. Hussain - http://www.maastaar.net
 *
 * This is an example of using FUSE to build a simple filesystem. It is a part of a tutorial in MQH Blog with the title "Writing Less Simple, Yet Stupid Filesystem Using FUSE in C": http://maastaar.net/fuse/linux/filesystem/c/2019/09/28/writing-less-simple-yet-stupid-filesystem-using-FUSE-in-C/
 *
 * License: GNU GPL
 */
 
#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>



// 加入aes演算法
#include "aes/aes.h"


// 模擬inode的結構
struct file{
	int idx;
	char name[ 256 ];
	char content[ 256 ];// 檔案內容
	struct file* next_file;
};
struct dir{
	char name[ 256 ];
	struct inode* content_inode;
	struct dir* next_dir;
};
// link list紀錄filelist, dir list 
struct inode{
	struct file* files_list; 	// files link list for this layer
	struct dir* dir_list;		// directory link list for this layer
};

// 初始化根目錄
struct inode temp_node= {.files_list = NULL, .dir_list = NULL};
struct inode * root_inode = &temp_node;

/*分析path
將一個char* 的path字串根據"/"拆成
ex: "dir1/dir2" => ["dir1", "dir2"]
*/ 
#define MAX_DIRS 100
char** split_path(const char *path, char delimiter, int *count) {
    char *temp_path;
    char delim[2] = {delimiter, '\0'};
    char *token;
    char **output;
    int dir_count = 0;

    // 拷貝原始字符串
    temp_path = strdup(path);
    if (temp_path == NULL) {
        perror("strdup failed");
        exit(EXIT_FAILURE);
    }

    // 分配指針數組的內存
    output = (char **)malloc(MAX_DIRS * sizeof(char *));
    if (output == NULL) {
        perror("malloc failed");
        free(temp_path);
        exit(EXIT_FAILURE);
    }

    // 使用strtok拆分字符串
    token = strtok(temp_path, delim);
    while (token != NULL && dir_count < MAX_DIRS) {
        output[dir_count] = strdup(token);
        if (output[dir_count] == NULL) {
            perror("strdup failed");
            // 釋放已分配的內存
            for (int i = 0; i < dir_count; i++) {
                free(output[i]);
            }
            free(output);
            free(temp_path);
            exit(EXIT_FAILURE);
        }
        dir_count++;
        token = strtok(NULL, delim);
    }

    free(temp_path); // 釋放臨時字符串的內存
    *count = dir_count;
    return output;
}
struct inode* trace_inode(char** path_list, int count){
	struct inode* current_inode = (struct inode*)malloc(sizeof(struct inode*));
	current_inode = root_inode;
	for(int i=0; i<count-1; i++){ // 留下path中的最後一組
		// 從當層的inode找dir
		struct dir* dir_ptr = current_inode->dir_list;
		while(dir_ptr!= NULL){
			if( strcmp( path_list[i], dir_ptr->name ) == 0 ){
				current_inode = dir_ptr->content_inode;
				break;
			}	
			dir_ptr = dir_ptr->next_dir;
		}
	}
	return current_inode;
}

// 
// 初始化函數
struct inode* create_inode() {
    struct inode* new_inode = (struct inode*)malloc(sizeof(struct inode));
    if (new_inode == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    new_inode->files_list = NULL;
	new_inode->dir_list = NULL;
    return new_inode;
}
// create_file funciton
struct file* create_file(){
	struct file* new_file = (struct file*)malloc(sizeof(struct file));
	memset(new_file->content, 0, sizeof(sizeof(char*)*256));
	memset(new_file->name, 0, sizeof(sizeof(char*)*256));
	new_file->idx = id_count++;
	return new_file;
}
void removeFile(struct file * prev_ptr, struct file * target_ptr){
	prev_ptr->next_file = target_ptr->next_file;
	free(target_ptr);
}

struct dir* create_dir(){
	struct dir* new_dir = (struct dir*)malloc(sizeof(struct dir));
	memset(new_dir->name, 0, sizeof(sizeof(char*)*256));
	new_dir->next_dir = NULL;
	return new_dir;
}

void add_dir( const char *dir_name )
{
	curr_dir_idx++;
	// 實體劃一個inode structure(必須分配記憶體空間)，要連在正確的inode下
	int path_len;
	char** path_list = split_path(dir_name, '/', &path_len);

	struct inode* current_inode = trace_inode(path_list, path_len);
	if(current_inode == NULL)
		printf("error in add_dir when trace inode!\n");

	struct inode * new_inode = create_inode();
	struct dir * new_dir = create_dir();
	
	strcpy(new_dir->name, path_list[path_len-1]);
	new_dir->content_inode = new_inode;

	// 插入到dir list中
	new_dir->next_dir = current_inode->dir_list;
	current_inode->dir_list = new_dir;


}

int is_dir( const char *path )
{
	path++; // Eliminating "/" in the path

    // 這邊要分析path，追著inode去判斷最後是不是對應到dir
	int path_len;
	char** path_list = split_path(path, '/', &path_len);
	
	struct inode* current_inode = trace_inode(path_list, path_len);
	int check = 0;
	struct dir* dir_ptr = current_inode->dir_list;
	while(dir_ptr && path_len){
		if( strcmp( path_list[path_len-1], dir_ptr->name ) == 0 ){
			check = 1;
			break;
		}	
		dir_ptr = dir_ptr->next_dir;
	}
	if(!check){
		return 0;
	}
	return 1;
}

void add_file( const char *path )
{
	int count;
	char** path_list = split_path(path, '/', &count);
	struct inode * current_inode = trace_inode(path_list, count);

	struct file* new_file = create_file();
	strcpy( new_file->name, path_list[count-1] );
	// 插入到file list中
	new_file->next_file = current_inode->files_list;
	current_inode->files_list = new_file;
}

int is_file( const char *path )
{
	//先找出inode
	int count;
	char** path_list = split_path(path, '/', &count);
	struct inode * current_inode = trace_inode(path_list, count);
	// 找到file
	int check = 0;
	struct file* file_ptr = current_inode->files_list;
	while(file_ptr && count){
		if( strcmp( path_list[count-1], file_ptr->name ) == 0 ){
			check = 1;
			break;
		}	
		file_ptr = file_ptr->next_file;
	}
	if(check)
		return 1;
	return 0;
}

int get_file_index( const char *path )
{

	path++; // Eliminating "/" in the path
	
	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 )
			return curr_idx;
	
	return -1;
}

void write_to_file( const char *path, const char *new_content )
{

	// write file
	//先找出inode
	int count;
	char** path_list = split_path(path, '/', &count);
	struct inode * current_inode = trace_inode(path_list, count);
	// 找到file
	int check = 0;
	struct file* file_ptr = current_inode->files_list;
	while(file_ptr && count){
		if( strcmp( path_list[count-1], file_ptr->name ) == 0 ){
			check = 1;
			break;
		}	
		file_ptr = file_ptr->next_file;
	}
	struct file* target_file = file_ptr;

		
	unsigned char* encrypted_data = encrypt(new_content, target_file->idx);
	
	//strcpy 內容
	strcpy( target_file->content, encrypted_data );  
}

// ... //

static int do_getattr( const char *path, struct stat *st )
{
	st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now
	
	if ( strcmp( path, "/" ) == 0 || is_dir( path ) == 1 )
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else if ( is_file( path ) == 1 )
	{
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}
	else
	{
		return -ENOENT;
	}
	
	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi )
{
	// 用inode tree找到當下路徑的inode並用該inode列出所有file和dir
	
	//這兩行不知道是什麼
	filler( buffer, ".", NULL, 0 ); // Current Directory
	filler( buffer, "..", NULL, 0 ); // Parent Directory
	
	// 跳到指定的路徑
	int count;
	char** path_list = split_path(path, '/', &count);
	struct inode * current_inode = trace_inode(path_list, count);
	struct dir* dir_ptr = current_inode->dir_list;
	while(dir_ptr && count){
		if( strcmp( path_list[count-1], dir_ptr->name ) == 0 ){
			current_inode = dir_ptr->content_inode;
			break;
		}	
		dir_ptr = dir_ptr->next_dir;
	}
	struct dir* dirlistptr = current_inode->dir_list;
	while(dirlistptr != NULL){
		filler( buffer, dirlistptr->name, NULL, 0 );
		dirlistptr = dirlistptr->next_dir;
	}
		
	struct file* filelistptr = current_inode->files_list;
	while(filelistptr){
		filler( buffer, filelistptr->name, NULL, 0 );
		filelistptr = filelistptr->next_file;
	}
	
	return 0;
}

static int do_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi )
{
	int path_len;
	char** path_list = split_path(path, '/', &path_len);
	struct inode * current_inode = trace_inode(path_list, path_len);
	// 找到file
	int check = 0;
	struct file* file_ptr = current_inode->files_list;
	while(file_ptr && path_len){
		if( strcmp( path_list[path_len-1], file_ptr->name ) == 0 )
			break;
		file_ptr = file_ptr->next_file;
	}
		

	char *content = file_ptr->content;
	content = decrypt(content, file_ptr->idx);
	memcpy( buffer, content + offset, sizeof(char*)*strlen(content) );
	
	return strlen( content ) - offset;
}

static int do_mkdir( const char *path, mode_t mode )
{
	path++;
	add_dir( path );
	
	return 0;
}

static int do_mknod( const char *path, mode_t mode, dev_t rdev )
{
	path++;
	add_file( path );
	
	return 0;
}

static int do_write( const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info )
{
	write_to_file( path, buffer );
	
	return size;
}
// TODO: rmdir
static int do_rmdir(const char * path){
	int path_len;
	char** path_list = split_path(path, '/', &path_len);
	struct inode* current_inode = trace_inode(path_list, path_len);
	struct dir* prev_dir = current_inode->dir_list;
	struct dir* dir_ptr = current_inode->dir_list;
	while(dir_ptr && path_len){
		if( strcmp( path_list[path_len-1], dir_ptr->name ) == 0 ){
			break;
		}	
		prev_dir = dir_ptr;
		dir_ptr = dir_ptr->next_dir;
	}
	if(dir_ptr == current_inode->dir_list){
		current_inode->dir_list = dir_ptr->next_dir;
		free(dir_ptr);
	}
	else{
		prev_dir->next_dir = dir_ptr->next_dir;
		free(dir_ptr);
	}
		
}
static int do_rm(const char * path){
	// rm file
	int path_len;
	char** path_list = split_path(path, '/', &path_len);
	struct inode* current_inode = trace_inode(path_list, path_len);
	struct file* prev_file = current_inode->files_list;
	struct file* file_ptr = current_inode->files_list;
	while(file_ptr && path_len){
		if( strcmp( path_list[path_len-1], file_ptr->name ) == 0 ){
			break;
		}	
		prev_file = file_ptr;
		file_ptr = file_ptr->next_file;
	}
	if(file_ptr == current_inode->files_list){
		current_inode->files_list = file_ptr->next_file;
		free(file_ptr);
	}
	else{
		prev_file->next_file = file_ptr->next_file;
		free(file_ptr);
	}
}

struct my_file_info {
    int fd; // 文件描述符
};
// TODO: open file

// TODO: close file


static struct fuse_operations operations = {
    .getattr	= do_getattr,
    .readdir	= do_readdir,
    .read		= do_read,
    .mkdir		= do_mkdir,
    .mknod		= do_mknod,
    .write		= do_write,
	.rmdir		= do_rmdir,
	.unlink		= do_rm,
};


int main( int argc, char *argv[] )
{
	return fuse_main( argc, argv, &operations, NULL );
}
