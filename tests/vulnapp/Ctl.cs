public class Ctl {
  public void A(string id) {
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id, conn);
    var bf = new BinaryFormatter();
    var md = MD5.Create();
  }
}
