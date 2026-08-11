-- 现有数据库必须先扩容密码字段，避免 Django 强哈希被截断。
ALTER TABLE `b_user`
  MODIFY COLUMN `password` varchar(128)
  CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL;
