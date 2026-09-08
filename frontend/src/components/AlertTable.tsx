type Alert={
    id:number;
    threat_type:string;
    severity:string;
    risk_score:number;
    source_ip:string;
    username:string | null;
    message: string;
    status: string;
    created_at: string;
};

type AlertTableProps={
    alerts:Alert[];
};

function AlertTable({alerts}: AlertTableProps){
    return(
        <div className="alert-section">
            <h2>Recent Security Alerts</h2>
            <div className="alert-table-container">
                <table className="alert-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Threat</th>
                            <th>Source IP</th>
                            <th>Severity</th>
                            <th>Risk</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alerts.map((alert)=>(
                            <tr key={alert.id}>
                                <td>#{alert.id}</td>
                                <td>{alert.threat_type}</td>
                                <td>{alert.source_ip}</td>
                                <td>
                                    <span className={`severity-badge ${alert.severity.toLowerCase()}`}>
                                        {alert.severity}
                                    </span>                                
                                </td>
                                <td>{alert.risk_score}</td>
                                <td>
                                    <span className={`status-badge ${alert.status.toLowerCase()}`}>
                                        {alert.status}
                                    </span>
                                </td>
                                <td>{new Date(alert.created_at).toLocaleString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default AlertTable;