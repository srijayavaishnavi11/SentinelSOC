import {useEffect, useState} from "react";
import {getDashboardStats, getAlerts} from "./api/api";
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck
} from "lucide-react";
import StatCard from "./components/StatCard";
import AlertTable from "./components/AlertTable";

type DashboardStats={
  total_events:number;
  total_alerts:number;
  alerts_by_status:{
    open:number;
    investigating:number;
    resolved:number;
  };
  alerts_by_severity:{
    critical:number;
    high:number;
    medium:number;
    low:number;
  };
};

type Alert={
  id:number;
  threat_type:string;
  severity:string;
  risk_score:number;
  source_ip:string;
  username: string | null;
  message:string;
  status:string;
  created_at:string;
};

function App(){
  const [stats,setStats]=useState<DashboardStats | null>(null);
  const [alerts,setAlerts]=useState<Alert[]>([]);
  const [error,setError]=useState<string | null>(null);
  useEffect(()=>{
    async function loadDashboard(){
      try{
        const statsData=await getDashboardStats();
        const alertsData=await getAlerts();
        setStats(statsData);
        setAlerts(alertsData);
      } catch(err){
        setError("Unable to load dashboard statistics.");
      }
    }
    loadDashboard();
  }, []); // Empty dependency array means this effect runs once on component mount

  if (error){
    return <h2>{error}</h2>;
  }

  if (!stats){
    return <h2>Loading SentinelSOC...</h2>;
  }

  return(
    <div className="dashboard">
      <header className="dashboard-header">
      <div>
      <h1>SentinelSOC</h1>
      <p>
        Security Operations Center
      </p>
      </div>
      </header>
      <section className="stats-grid">
        <StatCard
          title="Total Events"
          value={stats.total_events}
          icon={Activity}
        />
        <StatCard
          title="Total Alerts"
          value={stats.total_alerts}
          icon={ShieldAlert}
        />
        <StatCard
          title="Open Alerts"
          value={stats.alerts_by_status.open}
          icon={AlertTriangle}
        />
        <StatCard
          title="High Alerts"
          value={stats.alerts_by_severity.high}
          icon={ShieldCheck}
        />
      </section>
      <section className="severity-section">
        <h2>Alerts by Severity</h2>
        <div className="severity-list">
          <p>Critical: {stats.alerts_by_severity.critical}</p>
          <p>High: {stats.alerts_by_severity.high}</p>
          <p>Medium: {stats.alerts_by_severity.medium}</p>
          <p>Low: {stats.alerts_by_severity.low}</p>
        </div>
      </section>
      <AlertTable alerts={alerts}/>
    </div>
  );
}

export default App;