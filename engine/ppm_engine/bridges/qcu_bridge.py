"""Bridge to QCU (Quantum Computing Unit) from treesea project.
Used for ambiguity resolution: when multiple OEP candidates or path choices exist,
QCU quantum collapse selects the most probable one."""

from .base import IBridge


class QCUBridge(IBridge):
    @property
    def name(self) -> str:
        return "qcu"

    def available(self) -> bool:
        try:
            from qcu.runtime.runner import QCURunner
            return True
        except ImportError:
            return False

    def call(self, request: dict) -> dict:
        """Send a collapse request to QCU.
        request format: {candidates: [{id, payload: {entropy, branch_density, ...}}]}
        response: {winner: id, confidence: float}
        """
        # Build CollapseRequest from candidates
        try:
            from qcu.runtime.runner import QCURunner
            from qcu.scheduler.models import CollapseRequest, CandidateCluster, Candidate

            candidates = []
            for c in request.get("candidates", []):
                candidates.append(Candidate(
                    candidate_id=c["id"],
                    payload=c.get("payload", {})
                ))

            cluster = CandidateCluster(cluster_id="ppm_resolve", candidates=candidates)
            req = CollapseRequest(
                request_id=request.get("request_id", "ppm_auto"),
                qcu_session_id="ppm",
                clusters=[cluster]
            )

            runner = QCURunner()
            result = runner.run(req)

            # Extract winner from SeaOutputBundle
            if result.entries:
                best = max(result.entries, key=lambda e: abs(e.final_sz[0]) if e.final_sz else 0)
                return {"winner": best.label, "confidence": abs(best.final_sz[0]) if best.final_sz else 0}
            return {"error": "no result from QCU"}
        except Exception as e:
            return {"error": str(e)}
