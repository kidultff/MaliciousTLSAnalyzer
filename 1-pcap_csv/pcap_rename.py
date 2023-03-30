import os
from random import randint
path = "./"
filelist = os.listdir(path) #该文件夹下所有的文件（包括文件夹）

    
for file in filelist:   #遍历所有文件
    Olddir=os.path.join(path,file)   #原来的文件路径
    if os.path.isdir(Olddir):   #如果是文件夹则跳过
        continue  
        
    filename=os.path.splitext(file)[0]   #文件名
    filetype=os.path.splitext(file)[1]   #文件扩展名
    
    if '.py' == filetype:
        continue
    
    
    new_filename = filename + filetype
    new_filename = new_filename.replace('malspam', 'spam')
    new_filename = new_filename.replace('__', '_')
    
    
    
    if new_filename != Olddir:
        print(new_filename)
        os.rename(Olddir, new_filename)#重命名

