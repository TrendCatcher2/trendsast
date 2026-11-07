import java.io.*; import java.security.MessageDigest; import javax.xml.parsers.DocumentBuilderFactory;
import java.sql.*; import javax.servlet.http.*; import org.springframework.web.bind.annotation.*;
@RestController
public class Main {
  @GetMapping("/u")
  public String u(@RequestParam String id, Connection c) throws Exception {
    Statement st = c.createStatement();
    st.executeQuery("SELECT * FROM users WHERE id=" + id);
    Runtime.getRuntime().exec("ping " + id);
    new File("/data/" + id);
    return "ok";
  }
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String u = req.getParameter("next");
    resp.sendRedirect(u);
    new ObjectInputStream(req.getInputStream()).readObject();
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    MessageDigest.getInstance("MD5");
  }
}
