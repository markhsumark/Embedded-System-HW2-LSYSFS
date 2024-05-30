cd mountpoint


echo "test create file and create dir"
mkdir dir1
mkdir dir2
# touch file1.txt
echo "hello" >> file1.txt
echo "files and directorys in path mountpoint/" 
ls


echo "---make two dir and two file in dir1---"
mkdir dir1/dir11
mkdir dir1/dir12
echo "hello11" >> dir1/file11.txt
echo "hello12" >> dir1/file12.txt

echo "files and directorys in path mountpoint/dir1" 
ls dir1

echo ""
echo "test rmdir and rm"
echo ""
echo "---remove dir2 and dir1/dir11---"
rmdir dir2
rmdir dir1/dir11

echo "files and directorys in path mountpoint/" 
ls
echo "files and directorys in path mountpoint/dir1" 
ls dir1

echo ""
echo "---remove dir1/file11.txt and file1.txt---"
rm dir1/file11.txt
rm file1.txt

echo "files and directorys in path mountpoint/" 
ls
echo "files and directorys in path mountpoint/dir1" 
ls dir1


echo "--------done--------"