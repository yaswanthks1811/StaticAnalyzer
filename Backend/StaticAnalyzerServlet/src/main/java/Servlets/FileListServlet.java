package Servlets;

import DAO.FileInfoDao;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

@WebServlet("/analyzedFiles")
public class FileListServlet extends HttpServlet {
    ObjectMapper mapper = new ObjectMapper();

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        FileInfoDao fileInfoDao = new FileInfoDao();
        PrintWriter out = response.getWriter();

        try {
            String resp = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(fileInfoDao.getFileSummaryList());
            out.println(resp);
        } catch (SQLException e) {
            throw new ServletException("Database error", e);
        }
    }
}