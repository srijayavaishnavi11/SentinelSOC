import type { LucideIcon } from "lucide-react";

type StatCardProps={
    title:string;
    value:number;
    icon:LucideIcon;
};

function StatCard({
    title,
    value,
    icon: Icon
}:StatCardProps) {
    return(
        <div className="stat-card">
            <div className="stat-card-header">
                <span>
                    {title}
                </span>
                <Icon size={22} />
            </div>
            <div className="stat-card-value">
                {value}
            </div>
        </div>
    );
}

export default StatCard;