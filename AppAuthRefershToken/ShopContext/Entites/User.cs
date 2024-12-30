namespace AppAuthRefershToken.ShopContext.Entites
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;

        public string RefershToken { get; set; }
        public DateTime TokenCreate { get; set; } = DateTime.Now;
        public DateTime TokenExpire { get; set; }
    }
}
