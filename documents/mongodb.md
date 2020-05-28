### MongoDB

- 查看所有数据库 

  > show dbs

- 创建或切换数据库

  > use DB-Name

- 删除当前数据库

  > ```
  > db.dropDatabase()
  > ```



- 集合(表)

  - 创建

    > ```shell
    > db.createCollection(name, options)
    > > use test
    > switched to db test
    > > db.createCollection("runoob")
    > { "ok" : 1 }
    > >
    > ```

  - 查询

    > 使用 **show collections** 或 **show tables** 命令
    >
    > ```
    > > show collections
    > runoob
    > system.indexes
    > ```

  - 在 MongoDB 中，你不需要创建集合。当你插入一些文档时，MongoDB 会自动创建集合。

    > ```
    > > db.mycol2.insert({"name" : "菜鸟教程"})
    > > show collections
    > mycol2
    > ...
    > ```

  - 删除集合

    ```shell
    > use runoob
    switched to db runoob
    > db.createCollection("runoob")     # 先创建集合，类似数据库中的表
    > show tables
    runoob
    > db.runoob.drop()
    true
    > show tables
    ```


