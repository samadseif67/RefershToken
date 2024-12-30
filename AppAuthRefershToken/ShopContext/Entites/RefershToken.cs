namespace AppAuthRefershToken.ShopContext.Entites
{
    public class RefershToken
    {
        public  string Token { get; set; }
        public DateTime Create { get; set; }=DateTime.Now;
        public DateTime Expire { get; set; }
    }
}
