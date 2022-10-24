int main(int argc, char *argv[])
{
  int passwd;
  printf("IOLI Crackme Level 0x00\n");
  printf("Password: ");
  scanf("%d", &passwd);
  if (passwd == 3214)
    printf("Password OK :)\n");
  else
    printf("Invalid Password!\n");
  return 0;
}
