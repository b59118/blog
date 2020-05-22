# 删除github上的commit历史记录  

1. 创建新的分支
```shell
    git checkout  --orphan  new
    git add -A
    git commit -am "Re-init"
```
2. 删除原master分支, 重命名master, 并提交
   ```shell
    git branch  -D master
    git branch -m master
    git push origin master  -f

现在你再去GitHub上去看提交分支的记录，会发现只有一次提交了

