package org.apache.hadoop.hdfs.server.namenode;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ha.HAServiceProtocol;
import org.apache.hadoop.hdfs.protocol.HdfsConstants;
import org.apache.hadoop.hdfs.server.blockmanagement.BlockManager;
import org.apache.hadoop.security.UserGroupInformation;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.security.PrivilegedExceptionAction;
import java.util.Map;

public class NNStatServlet extends DfsServlet{

    /** for java.io.Serializable */
    private static final long serialVersionUID = 154678944556214511L;

    /** Handle fsck request */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response
    ) throws IOException {
        try {
            HAServiceProtocol.HAServiceState stat = getNNStat();
            boolean isActive = stat.equals( HAServiceProtocol.HAServiceState.ACTIVE );
            final PrintWriter out = response.getWriter();
            if( isActive ){
                response.setStatus(200);
            }else{
                response.setStatus(222);
            }
            out.print(stat);
        } catch (Exception e) {
            LOG.info("get NameNode stat in NNStatServlet failed.",e);
            response.sendError(400, e.getMessage());
        }
    }

    public HAServiceProtocol.HAServiceState getNNStat() throws Exception{
        ServletContext context = getServletContext();
        NameNode nn = NameNodeHttpServer.getNameNodeFromContext(context);
        return nn.getServiceStatus().getState();
    }
}
