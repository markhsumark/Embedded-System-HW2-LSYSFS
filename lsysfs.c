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

// ... //

char dir_list[ 256 ][ 256 ];
int curr_dir_idx = -1;

char files_list[ 256 ][ 256 ];
int curr_file_idx = -1;

char files_content[ 256 ][ 256 ];
int curr_file_content_idx = -1;

// TODO: 模擬inode的結構
struct file{
	char files_content[ 256 ];// 檔案內容
};
struct inode{
	int file_count;
	int dir_count;
	char dir_name_list[ 256 ][ 256 ];
	char file_name_list[ 256 ][ 256 ];
	struct file* files_list[ 256 ]; // file index to file
	struct inode* dir_list[ 256 ];
};

// TODO: 初始化根目錄
struct inode temp_node= {.file_count = -1, .dir_count = -1};
struct inode * root_inode = &temp_node;

/*TODO: 分析path
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

// TODO
// 初始化函數
struct inode* create_inode() {
    struct inode* new_inode = (struct inode*)malloc(sizeof(struct inode));
    if (new_inode == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    new_inode->file_count = -1;
    new_inode->dir_count = -1;
    // 清空其他成員（初始化為零）
    memset(new_inode->dir_name_list, 0, sizeof(sizeof(char*)*256*256));
    memset(new_inode->file_name_list, 0, sizeof(sizeof(char*)*256*256));
    memset(new_inode->files_list, 0, sizeof(new_inode->files_list));
    memset(new_inode->dir_list, 0, sizeof(new_inode->dir_list));
    return new_inode;
}

void add_dir( const char *dir_name )
{
	printf("\nin add_dir)\n");
	curr_dir_idx++;
	// TODO: 實體劃一個inode structure(必須分配記憶體空間)，要連在正確的inode下
	int count;
	char** path_list = split_path(dir_name, '/', &count);
	struct inode * current_inode = root_inode;
	for(int i=0; i<count-1; i++){
		// 從當層的inode找dir
		for(int d=0; d<=current_inode->dir_count; d++){
			printf("find %s\n", path_list[i]);
			if( strcmp( path_list[i], current_inode->dir_name_list[d] ) == 0 ){
				current_inode = current_inode->dir_list[d];
				printf("goto %s's inode\n", current_inode->dir_name_list[d]);
				break;
			}	
		}
	}
	int n = ++(current_inode->dir_count);	
	strcpy(current_inode->dir_name_list[n], path_list[count-1]);
	struct inode * new_inode = create_inode();
	printf("create a inode %s\n", path_list[count-1]);
	current_inode->dir_list[n] = new_inode;

	strcpy( dir_list[ curr_dir_idx ], dir_name );
}

int is_dir( const char *path )
{
	path++; // Eliminating "/" in the path

    // TODO: 這邊要分析path，追著inode去判斷最後是不是對應到dir
	printf("\nin is_dir)\n");
	int count;
	char** path_list = split_path(path, '/', &count);
	struct inode * current_inode = root_inode;
	int check = 0;
	for(int i=0; i<count; i++){
		// 從當層的inode找dir
		for(int d=0; d<=current_inode->dir_count; d++){
			printf("find %s\n", path_list[i]);
			if( strcmp( path_list[i], current_inode->dir_name_list[d] ) == 0 ){
				printf("goto %s's inode\n", path_list[i]);
				current_inode = current_inode->dir_list[d];
				check = 1;
			}
		}
		if(!check){
			printf("this is not dir!!\n");
			return 0;
		}
	}
	printf("done is_dir\n");

	
	for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
		if ( strcmp( path, dir_list[ curr_idx ] ) == 0 )
			return 1;
	
	return 0;
}

void add_file( const char *filename )
{
	curr_file_idx++;
	strcpy( files_list[ curr_file_idx ], filename );
	
	curr_file_content_idx++;
	strcpy( files_content[ curr_file_content_idx ], "" );
}

int is_file( const char *path )
{
	path++; // Eliminating "/" in the path
	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 )
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
	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 ) // No such file
		return;
	// todo : 這裡要放入加密程式碼

	unsigned char* encrypted_data = encrypt(new_content, file_idx);
	strcpy( files_content[ file_idx ], encrypted_data ); 
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
	printf("\ndo_readdir)%s\n", path);
	// TODO: 用inode tree找到當下路徑的inode並用該inode列出所有file和dir
	
	//這兩行不知道是什麼
	filler( buffer, ".", NULL, 0 ); // Current Directory
	filler( buffer, "..", NULL, 0 ); // Parent Directory
	
	// 跳到指定的路徑
	int count;
	char** path_list = split_path(path, '/', &count);
	struct inode * current_inode = root_inode;
	for(int i=0; i<count; i++){
		// 從當層的inode找dir
		for(int d=0; d<=current_inode->dir_count; d++){
			printf("find %s\n", path_list[i]);
			if( strcmp( path_list[i], current_inode->dir_name_list[d] ) == 0 ){
				current_inode = current_inode->dir_list[d];
				printf("goto %s's inode\n", current_inode->dir_name_list[d]);
				break;
			}	
		}
	}
	for ( int curr_idx = 0; curr_idx <= current_inode->dir_count; curr_idx++ )
		filler( buffer, current_inode->dir_name_list[ curr_idx ], NULL, 0 );

	for ( int curr_idx = 0; curr_idx <= current_inode->file_count; curr_idx++ )
		filler( buffer, current_inode->file_name_list[ curr_idx ], NULL, 0 );
	
	return 0;
}

static int do_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi )
{
	int file_idx = get_file_index( path );
	
	if ( file_idx == -1 )
		return -1;
	
	char *content = files_content[ file_idx ];
	// todo : 這裡要放入解密程式碼，考慮要不要用id去對應key

	char * decrypted_data = decrypt(content, file_idx);
	memcpy( buffer, decrypted_data + offset, size );
	
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
	printf("do write!!\n");
	write_to_file( path, buffer );
	
	return size;
}

static int do_rmdir(const char * ){
	
}

static struct fuse_operations operations = {
    .getattr	= do_getattr,
    .readdir	= do_readdir,
    .read		= do_read,
    .mkdir		= do_mkdir,
    .mknod		= do_mknod,
    .write		= do_write,
};

int main( int argc, char *argv[] )
{
	return fuse_main( argc, argv, &operations, NULL );
}
