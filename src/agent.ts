import {
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
  TransactionEvent,
} from "forta-agent";

export const ERC20_TRANSFERFROM_SIGNATURE =
  "function transferFrom(address,address,uint256)";

let findingsCount = 0;

const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const findings: Finding[] = [];

  const transferFromCalls = txEvent.filterFunction(
    ERC20_TRANSFERFROM_SIGNATURE
  );

  transferFromCalls.forEach((call) => {
    // Normalize addresses and provide fallback for null values
    const fromAddressNormalized = call.args.from
      ? call.args.from.toLowerCase()
      : "N/A";
    const txSenderNormalized = txEvent.from
      ? txEvent.from.toLowerCase()
      : "N/A";
    const toAddressNormalized = txEvent.to ? txEvent.to.toLowerCase() : "N/A";

    if (
      txSenderNormalized !== fromAddressNormalized &&
      txSenderNormalized !== "N/A" &&
      fromAddressNormalized !== "N/A"
    ) {
      findings.push(
        Finding.fromObject({
          name: "Suspicious transferFrom Call",
          description: `transferFrom called by different msg.sender: ${txSenderNormalized}`,
          alertId: "FORTA-2",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            from: fromAddressNormalized,
            messageSender: txSenderNormalized,
            interactedWith: toAddressNormalized,
          },
        })
      );
      findingsCount++;
    }
  });

  return findings;
};

export default {
  handleTransaction,
};
